package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/itchio/butler/runner/macutil"

	"github.com/chzyer/readline"
	"github.com/go-errors/errors"
	prettyjson "github.com/hokaccha/go-prettyjson"
	"gopkg.in/alecthomas/kingpin.v2"
)

var verbose *bool

func main() {
	app := kingpin.New("buse-cli", "A dumb CLI for butler service")
	verbose = app.Flag("verbose", "Show full input & output").Bool()

	log.SetFlags(0)

	_, err := app.Parse(os.Args[1:])
	must(err)

	must(doMain())
}

func doMain() error {
	historyFile := filepath.Join(os.TempDir(), "buse-cli-history")
	normalPrompt := "\033[31m»\033[0m "
	pendingPrompt := "\033[31m◴\033[0m "

	var completer = readline.NewPrefixCompleter(
		readline.PcItem("r",
			readline.PcItem("Version.Get"),
			readline.PcItem("Session.List"),
		),
		readline.PcItem("n"),
		readline.PcItem("st"),
	)

	l, err := readline.NewEx(&readline.Config{
		Prompt:          normalPrompt,
		HistoryFile:     historyFile,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    completer,

		HistorySearchFold: true,
	})
	if err != nil {
		return errors.Wrap(err, 0)
	}
	defer l.Close()
	log.SetOutput(color.Output)

	log.Printf("Welcome to buse's dumb CLI")

	f := prettyjson.NewFormatter()
	f.KeyColor = color.New(color.FgBlue, color.Bold)

	var itchPath = ""
	switch runtime.GOOS {

	case "windows":
		appData := os.Getenv("APPDATA")
		itchPath = filepath.Join(appData, "itch")
	case "linux":
		configPath := os.Getenv("XDG_CONFIG_HOME")
		if configPath != "" {
			itchPath = filepath.Join(configPath, "itch")
		} else {
			homePath := os.Getenv("HOME")
			itchPath = filepath.Join(homePath, ".config", "itch")
		}
	case "darwin":
		appSupport, err := macutil.GetApplicationSupportPath()
		if err != nil {
			return errors.Wrap(err, 0)
		}
		itchPath = filepath.Join(appSupport, "itch")
	}
	dbPath := filepath.Join(itchPath, "db", "butler.db")

	log.Printf("Using DB path (%s)", dbPath)

	cmd := exec.Command("butler",
		"service",
		"-j",
		"--dbpath", dbPath,
	)

	pr, pw, err := os.Pipe()
	if err != nil {
		return errors.Wrap(err, 0)
	}
	cmd.Stdout = pw
	cmd.Stderr = l.Stderr()

	go func() {
		must(cmd.Start())
		defer cmd.Process.Kill()
		must(cmd.Wait())
		log.Print("Butler exited!")
	}()

	addrChan := make(chan string)
	go func() {
		s := bufio.NewScanner(pr)
		for s.Scan() {
			line := s.Bytes()

			m := make(map[string]interface{})
			err := json.Unmarshal(line, &m)
			if err != nil {
				if *verbose {
					time.Sleep(250 * time.Millisecond)
					log.Printf("[butler]: %s", string(line))
					l.Refresh()
				}
				continue
			}

			if m["type"] == "result" {
				valMap := m["value"].(map[string]interface{})
				if valMap["type"] == "server-listening" {
					addrChan <- valMap["address"].(string)
				}
			} else {
				log.Printf("[butler]: %s", string(line))
				continue
			}
		}
	}()

	addr := <-addrChan
	if *verbose {
		log.Printf("Connecting to %s...", addr)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	pretty := func(input interface{}) string {
		out, err := f.Marshal(input)
		must(err)
		return string(out)
	}

	pendingReqs := make(map[int64]string)
	var pendingMutex sync.Mutex

	pushRequest := func(id int64, method string) {
		pendingMutex.Lock()
		defer pendingMutex.Unlock()

		pendingReqs[id] = method
		l.SetPrompt(pendingPrompt)
	}
	getRequest := func(m map[string]interface{}) string {
		pendingMutex.Lock()
		defer pendingMutex.Unlock()

		reqId := int64(m["id"].(float64))
		pr := pendingReqs[reqId]
		delete(pendingReqs, reqId)

		if len(pendingReqs) == 0 {
			l.SetPrompt(normalPrompt)
		}

		if pr == "" {
			return "<Unknown request>"
		}
		return pr
	}

	var lastStack = ""
	go func() {
		s := bufio.NewScanner(conn)
		for s.Scan() {
			line := s.Bytes()

			time.Sleep(time.Millisecond * 250)

			prettyLine, err := f.Format(line)
			must(err)

			if *verbose {
				log.Printf("← %s", string(prettyLine))
			} else {
				m := make(map[string]interface{})
				must(json.Unmarshal(line, &m))

				if _, ok := m["error"]; ok {
					if e, ok := m["error"].(map[string]interface{}); ok {
						log.Printf("⚠ %s (Code %d): %s\n", getRequest(m), int64(e["code"].(float64)), e["message"])
						if data, ok := e["data"].(map[string]interface{}); ok {
							lastStack = data["stack"].(string)
						} else {
							lastStack = ""
						}
					} else {
						log.Printf("\n Error we can't unwrap: %s\n", pretty(m))
					}
				} else if _, ok := m["result"]; ok {
					log.Printf("← %s: %s\n", getRequest(m), pretty(m["result"]))
				} else if _, ok := m["id"]; ok {
					log.Printf("→ %.0f %s: %s\n", m["id"], m["method"], pretty(m["params"]))
				} else if _, ok := m["params"]; ok {
					log.Printf("✉ %s\n", pretty(m["params"]))
				} else {
					log.Printf(" Not sure what: %s\n", pretty(m))
				}
			}
			l.Refresh()
		}
	}()

	var id int64

	sendCommand := func(line string) error {
		line = strings.TrimSpace(line)

		rootTokens := strings.SplitN(line, " ", 2)
		if len(rootTokens) != 2 {
			switch line {
			case "q", "quit", "exit":
				log.Printf("Bye!")
				os.Exit(0)
			case "st":
				time.Sleep(250 * time.Millisecond)
				if lastStack == "" {
					log.Printf("No stack trace available!")
				} else {
					log.Printf("============================")
					log.Printf("Last stack trace:")
					log.Printf(lastStack)
					log.Printf("============================")
				}
				l.Refresh()
			default:
				return fmt.Errorf("Unknown command '%s'", line)
			}
			return nil
		}

		kind := rootTokens[0]
		rest := rootTokens[1]

		req := make(map[string]interface{})
		req["jsonrpc"] = "2.0"

		var payload string
		var payloadField string

		switch kind {
		case "r":
			payloadField = "params"
			tokens := strings.SplitN(rest, " ", 2)
			req["method"] = tokens[0]
			if len(tokens) >= 2 {
				payload = tokens[1]
			} else {
				payload = "{}"
			}
			req["id"] = id
			id++
		case "n":
			payloadField = "params"
			tokens := strings.SplitN(rest, " ", 2)
			req["method"] = tokens[0]
			if len(tokens) >= 2 {
				payload = tokens[1]
			} else {
				payload = "{}"
			}
		default:
			// must be a reply
			payloadField = "result"
			payload = rest

			reqID, err := strconv.ParseInt(kind, 10, 64)
			if err != nil {
				return fmt.Errorf("Invalid command (%s): must be 'r' (request), 'n' (notification), or a request ID to reply to", kind)
			}

			req["id"] = reqID
		}

		payloadObj := make(map[string]interface{})
		err = json.Unmarshal([]byte(payload), &payloadObj)
		if err != nil {
			return errors.WrapPrefix(err, "while parsing params", 0)
		}
		req[payloadField] = payloadObj

		reqBytes, err := json.Marshal(req)
		if err != nil {
			return errors.WrapPrefix(err, "while marshalling request", 0)
		}

		if *verbose {
			prettyInput, err := f.Format(reqBytes)
			if err != nil {
				return errors.WrapPrefix(err, "while pretty-printing request", 0)
			}

			log.Printf("\n→ %s\n", string(prettyInput))
		}

		_, err = conn.Write(reqBytes)
		if err != nil {
			return errors.Wrap(err, 0)
		}
		_, err = conn.Write([]byte{'\n'})
		if err != nil {
			return errors.Wrap(err, 0)
		}

		switch kind {
		case "r":
			pushRequest(req["id"].(int64), req["method"].(string))
		}

		return nil
	}

	startTime := time.Now()
	for {
		line, err := l.Readline()
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Printf("")
				log.Printf("Got EOF, bye now!")
				totalDuration := time.Since(startTime)
				if totalDuration.Seconds() < 1 {
					log.Printf("\n")
					log.Printf("(Note: that was, like, really quick, did something go wrong?)")
					log.Printf("(If you're on msys/cygwin, you may want to run `winpty buse-cli` instead)")
				}

				return nil
			}
			return errors.Wrap(err, 0)
		}

		err = sendCommand(line)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
			log.Printf("⚠ %s", err.Error())
			l.Refresh()
		}
	}

	return nil
}

func must(err error) {
	if err == nil {
		return
	}

	if se, ok := err.(*errors.Error); ok {
		log.Fatal(se.ErrorStack())
	} else {
		log.Fatal(err.Error())
	}
}
