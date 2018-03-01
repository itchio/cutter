package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/itchio/butler/buse/busegen/spec"
	"github.com/itchio/butler/runner/macutil"

	"github.com/chzyer/readline"
	"github.com/go-errors/errors"
	prettyjson "github.com/hokaccha/go-prettyjson"
	"gopkg.in/alecthomas/kingpin.v2"
)

var verbose *bool
var sessionID int64

var ErrCycle = errors.New("cycle")

func main() {
	app := kingpin.New("buse-cli", "A dumb CLI for butler service")
	verbose = app.Flag("verbose", "Show full input & output").Bool()

	log.SetFlags(0)
	log.SetOutput(color.Output)

	_, err := app.Parse(os.Args[1:])
	must(err)

	for {
		err := doMain()
		if err != nil {
			if errors.Is(err, ErrCycle) {
				rebuild()
				log.Printf("")
				log.Printf("~~~~~~~~~~~ chaaaaaaaaaaaaange places! ~~~~~~~~~~~")
				log.Printf("")
				continue
			}
		}
		must(err)
		break
	}
}

func doMain() error {
	historyFile := filepath.Join(os.TempDir(), "buse-cli-history")
	normalPrompt := "\033[31m»\033[0m "
	pendingPrompt := "\033[31m◴\033[0m "

	buseSpec := &spec.Spec{}
	readSpec := func() error {
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			return errors.New("GOPATH not set")
		}

		specPath := path.Join(gopath, "src", "github.com", "itchio", "butler", "buse", "busegen", "spec", "buse.json")

		specBytes, err := ioutil.ReadFile(specPath)
		if err != nil {
			if os.IsNotExist(err) {
				// try something funky for msys2 setups
				output, oErr := exec.Command("cygpath", "-w", specPath).CombinedOutput()
				if oErr == nil {
					specPath = strings.TrimSpace(string(output))
					specBytes, err = ioutil.ReadFile(specPath)
				}
			}

			if err != nil {
				return errors.Wrap(err, 0)
			}
		}

		err = json.Unmarshal(specBytes, buseSpec)
		if err != nil {
			return errors.Wrap(err, 0)
		}
		return nil
	}

	err := readSpec()
	if err != nil {
		log.Printf("Could not read buse spec: %s", err.Error())
	}

	requestCompletion := func() readline.PrefixCompleterInterface {
		var items []readline.PrefixCompleterInterface
		for _, req := range buseSpec.Requests {
			if req.Caller == "client" {
				items = append(items, readline.PcItem(req.Method))
			}
		}

		return readline.PcItem("r", items...)
	}

	notificationCompletion := func() readline.PrefixCompleterInterface {
		var items []readline.PrefixCompleterInterface
		for _, not := range buseSpec.Notifications {
			items = append(items, readline.PcItem(not.Method))
		}

		return readline.PcItem("n", items...)
	}

	docCompletion := func() readline.PrefixCompleterInterface {
		var items []readline.PrefixCompleterInterface
		for _, not := range buseSpec.Notifications {
			items = append(items, readline.PcItem(not.Method))
		}
		for _, req := range buseSpec.Requests {
			items = append(items, readline.PcItem(req.Method))
		}
		for _, t := range buseSpec.StructTypes {
			items = append(items, readline.PcItem(t.Name))
		}
		for _, t := range buseSpec.EnumTypes {
			items = append(items, readline.PcItem(t.Name))
		}

		return readline.PcItem("doc", items...)
	}

	var completer = readline.NewPrefixCompleter(
		requestCompletion(),
		notificationCompletion(),
		docCompletion(),
		readline.PcItem("st"),
		readline.PcItem("s"),
		readline.PcItem("help"),
		readline.PcItem("exit"),
	)

	l, err := readline.NewEx(&readline.Config{
		Prompt:          "",
		HistoryFile:     historyFile,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    completer,

		HistorySearchFold: true,
	})
	if err != nil {
		return errors.Wrap(err, 0)
	}
	defer func() {
		l.Close()
	}()

	f := prettyjson.NewFormatter()

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

	dbExists := true
	_, err = os.Stat(dbPath)
	if err != nil {
		dbExists = false
	}

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
		err := cmd.Wait()
		if err != nil {
			log.Printf("butler exited with error: %s", err.Error())
		}
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
					log.Printf("[butler]: %s", string(line))
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
		must(s.Err())
	}()

	addr := <-addrChan
	if *verbose {
		log.Printf("Connecting to %s...", addr)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	defer conn.Close()

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
		l.Refresh()
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

	logFields := func(name string, fields []*spec.FieldSpec) {
		if len(fields) == 0 {
			log.Printf("%s: none", color.YellowString(name))
			return
		}

		log.Printf("%s: ", color.YellowString(name))
		log.Printf("")
		for _, field := range fields {
			log.Printf("  - %s: %s", color.RedString(field.Name), color.BlueString(field.Type))
			log.Printf("    %s", field.Doc)
		}
	}

	logEnumValues := func(name string, fields []*spec.EnumValueSpec) {
		if len(fields) == 0 {
			log.Printf("%s: none", color.YellowString(name))
			return
		}

		log.Printf("%s: ", color.YellowString(name))
		log.Printf("")
		for _, field := range fields {
			log.Printf("  - %s: %s", color.RedString(field.Name), color.BlueString(field.Value))
			log.Printf("    %s", field.Doc)
		}
	}

	requestsByMethod := make(map[string]*spec.RequestSpec)
	for _, req := range buseSpec.Requests {
		requestsByMethod[req.Method] = req
	}
	notificationsByMethod := make(map[string]*spec.NotificationSpec)
	for _, not := range buseSpec.Notifications {
		notificationsByMethod[not.Method] = not
	}
	structTypesByMethod := make(map[string]*spec.StructTypeSpec)
	for _, t := range buseSpec.StructTypes {
		structTypesByMethod[t.Name] = t
	}
	enumTypesByMethod := make(map[string]*spec.EnumTypeSpec)
	for _, t := range buseSpec.EnumTypes {
		enumTypesByMethod[t.Name] = t
	}

	hasDoc := func(name string) bool {
		if _, ok := requestsByMethod[name]; ok {
			return true
		}
		if _, ok := notificationsByMethod[name]; ok {
			return true
		}
		if _, ok := structTypesByMethod[name]; ok {
			return true
		}
		if _, ok := enumTypesByMethod[name]; ok {
			return true
		}
		return false
	}

	showDoc := func(name string) {
		hang()
		defer l.Refresh()

		if req, ok := requestsByMethod[name]; ok {
			log.Printf("")
			log.Printf("%s (%s Request)", color.GreenString(req.Method), req.Caller)
			log.Printf("")
			log.Printf(req.Doc)
			log.Printf("")
			logFields("Parameters", req.Params.Fields)
			log.Printf("")
			logFields("Result", req.Result.Fields)
			log.Printf("")
			return
		}

		if not, ok := notificationsByMethod[name]; ok {
			log.Printf("")
			log.Printf("%s (Notification)", color.GreenString(not.Method))
			log.Printf("")
			log.Printf(not.Doc)
			log.Printf("")
			logFields("Parameters", not.Params.Fields)
			log.Printf("")
			return
		}

		if t, ok := structTypesByMethod[name]; ok {
			log.Printf("")
			log.Printf("%s (Struct)", color.GreenString(t.Name))
			log.Printf("")
			log.Printf(t.Doc)
			log.Printf("")
			logFields("Fields", t.Fields)
			log.Printf("")
			return
		}

		if t, ok := enumTypesByMethod[name]; ok {
			log.Printf("")
			log.Printf("%s (Enum)", color.GreenString(t.Name))
			log.Printf("")
			log.Printf(t.Doc)
			log.Printf("")
			logEnumValues("Values", t.Values)
			log.Printf("")
			return
		}

		log.Printf("No doc found for '%s'", name)
	}

	var lastMethod = ""
	var lastStack = ""
	go func() {
		s := bufio.NewScanner(conn)
		connBuffSize := 16 * 1024 * 1024 // 16MiB
		s.Buffer(make([]byte, connBuffSize), connBuffSize)
		for s.Scan() {
			line := s.Bytes()

			hang()

			prettyLine, err := f.Format(line)
			must(err)

			if *verbose {
				log.Printf("← %s", string(prettyLine))
			}

			prettyResult := func(result interface{}) string {
				resultString := pretty(result)
				resultLines := strings.Split(resultString, "\n")
				if len(resultLines) > 60 {
					temp := append(resultLines[0:30], color.YellowString("..................... snip ....................."))
					temp = append(temp, resultLines[len(resultLines)-30:]...)
					resultLines = temp
				}
				return strings.Join(resultLines, "\n")
			}

			{
				m := make(map[string]interface{})
				must(json.Unmarshal(line, &m))

				if _, ok := m["error"]; ok {
					if e, ok := m["error"].(map[string]interface{}); ok {
						method := getRequest(m)
						log.Printf("⚠ %s (Code %d):", color.GreenString(method), int64(e["code"].(float64)))
						log.Printf("    %s", color.RedString(e["message"].(string)))
						if hasDoc(method) {
							log.Printf("(Use the 'doc' command to learn more about %s)", color.GreenString(method))
						}
						if data, ok := e["data"].(map[string]interface{}); ok {
							lastStack = data["stack"].(string)
							log.Printf("(Use the 'st' command to see a full stack trace)")
						} else {
							lastStack = ""
						}
					} else {
						log.Printf("\n Error we can't unwrap: %s\n", pretty(m))
					}
				} else if _, ok := m["result"]; ok {
					// reply to one or our requests
					method := getRequest(m)
					log.Printf("← %s: %s\n", color.GreenString(method), prettyResult(m["result"]))
				} else if _, ok := m["id"]; ok {
					// server request
					method := m["method"].(string)
					lastMethod = method
					log.Printf("→ %s: %s\n", color.GreenString(method), pretty(m["params"]))
					log.Printf("(Reply to this server request with '%.0f [json payload]')", m["id"])
					if hasDoc(method) {
						log.Printf("(Use the 'doc' command to learn more about %s)", color.GreenString(method))
					}
				} else if _, ok := m["params"]; ok {
					// notification
					method := m["method"].(string)
					log.Printf("✉ %s %s\n", color.GreenString(method), prettyResult(m["params"]))
				} else {
					log.Printf(" Not sure what: %s\n", pretty(m))
				}
			}
			l.Refresh()
		}
		err := s.Err()
		if err != nil {
			if _, ok := err.(net.Error); ok {
				if strings.Contains(err.Error(), "use of closed") {
					// that's ok
					return
				}
				log.Printf("network error: %s", err.Error())
				return
			}
			must(err)
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
				hang()
				if lastStack == "" {
					log.Print("No stack trace available!")
				} else {
					log.Print("============================")
					log.Print("Last stack trace:")
					log.Print(lastStack)
					log.Print("============================")
				}
				l.Refresh()
			case "doc":
				// doc for the latest command
				if lastMethod != "" {
					showDoc(lastMethod)
				}
			case "rb":
				return ErrCycle
			case "help", "h":
				hang()
				log.Printf("")
				log.Printf("Commands: ")
				log.Printf("")
				log.Printf("  %s", color.YellowString("r method [params]"))
				log.Printf("    Send an rpc request. params is a JSON object, defaults to {}")
				log.Printf("")
				log.Printf("    Example: %s", color.BlueString("r Version.Get"))
				log.Printf("    Example: %s", color.BlueString(fmt.Sprintf("r Test.DoubleTwice {%#v: 4}", "number")))
				log.Printf("")
				log.Printf("  %s", color.YellowString("id [result]"))
				log.Printf("    Reply to one of butler's rpc requests. result is a JSON object, defaults to {}")
				log.Printf("")
				log.Printf("  	Example: %s", color.BlueString(fmt.Sprintf("0 {%#v: 8}", "number")))
				log.Printf("")
				log.Printf("  %s", color.YellowString("n method [params]"))
				log.Printf("    Send an rpc notification. params is a JSON object, defaults to {}")
				log.Printf("")
				log.Printf("  %s", color.YellowString("doc [method]"))
				log.Printf("    Display the documentation for a method (or the last request sent/received)")
				log.Printf("")
				log.Printf("  %s", color.YellowString("st"))
				log.Printf("    Display a stack trace for the last error we got, if available.")
				log.Printf("")
				log.Printf("  %s", color.YellowString("s [id]"))
				log.Printf("    Set sessionId to [id] automatically for all future requests")
				log.Printf("")
				log.Printf("  %s", color.YellowString("q"))
				log.Printf("    Quit")
				log.Printf("")
				l.Refresh()
			default:
				return fmt.Errorf("Unknown command '%s'", line)
			}
			return nil
		}

		kind := rootTokens[0]
		rest := rootTokens[1]

		if kind == "doc" {
			showDoc(rest)
			return nil
		}

		if kind == "s" {
			sessionID, err = strconv.ParseInt(rest, 10, 64)
			if err != nil {
				return errors.Wrap(err, 0)
			}

			log.Print(color.YellowString(fmt.Sprintf("Switched to session %d", sessionID)))
			return nil
		}

		req := make(map[string]interface{})
		req["jsonrpc"] = "2.0"

		var payload string
		var payloadField string
		var addSessionID bool

		switch kind {
		case "r":
			payloadField = "params"
			tokens := strings.SplitN(rest, " ", 2)
			method := tokens[0]

			if rs, ok := requestsByMethod[method]; ok {
				for _, f := range rs.Params.Fields {
					if f.Name == "sessionId" {
						addSessionID = true
					}
				}
			}

			req["method"] = method
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

		// if we have a sessionID set
		if addSessionID {
			// ... and it's not included in the payload yet
			if _, ok := payloadObj["sessionId"]; !ok {
				if sessionID != 0 {
					// then add it
					payloadObj["sessionId"] = sessionID
				} else {
					// or tell the user about 's'
					log.Printf("%s", color.RedString("You're missing a 'sessionId' parameter"))
					log.Printf("You can use the %s command to set a session ID for all requests", color.GreenString("s [id]"))
				}
			}
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
			lastMethod = req["method"].(string)
		}

		return nil
	}

	log.Printf("Thanks for flying buse-cli!")
	log.Printf("Using DB (%s)", dbPath)
	if !dbExists {
		log.Printf("(Warning: This file did not exist when buse-cli started up!)")
	}
	log.Printf("Type 'help' for the cliff notes.")
	l.SetPrompt(normalPrompt)
	l.Refresh()

	startTime := time.Now()
	for {
		line, err := l.Readline()
		if err != nil {
			if errors.Is(err, io.EOF) {
				totalDuration := time.Since(startTime)
				if totalDuration.Seconds() < 0.5 {
					log.Printf("Got super early EOF, if you're on msys/cygwin you might want to call `winpty buse-cli` instead.")
				}
				log.Printf("")
				log.Printf("Got EOF, bye now!")

				return nil
			}

			if errors.Is(err, readline.ErrInterrupt) {
				l.Refresh()
				continue
			}
			return errors.Wrap(err, 0)
		}

		err = sendCommand(line)
		if err != nil {
			if errors.Is(err, ErrCycle) {
				return err
			}
			hang()
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

func rebuild() {
	hang()
	log.Printf("Rebuilding...")
	bash := func(command string) error {
		startTime := time.Now()

		log.Print(color.HiBlueString(fmt.Sprintf("$ %s", command)))
		cmd := exec.Command("bash", "-c", command)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Print(color.RedString("Command failed, log follows:"))
			log.Print(string(out))
			return err
		}
		log.Printf("(Took %s)", time.Since(startTime))
		return nil
	}

	err := bash("go get -v github.com/itchio/butler/buse/busegen")
	if err != nil {
		log.Print(color.RedString(fmt.Sprintf("Could not build busegen: %s", err.Error())))
		return
	}

	err = bash("busegen godocs")
	if err != nil {
		log.Print(color.RedString(fmt.Sprintf("Could not generate spec: %s", err.Error())))
		return
	}

	err = bash("go get -v github.com/itchio/butler")
	if err != nil {
		log.Print(color.RedString(fmt.Sprintf("Could not build butler: %s", err.Error())))
		return
	}
}

func hang() {
	time.Sleep(100 * time.Millisecond)
}
