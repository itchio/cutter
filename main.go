package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/fatih/color"
	"github.com/itchio/butler/butlerd/generous/spec"

	"github.com/alecthomas/kingpin/v2"
	"github.com/chzyer/readline"
	"github.com/go-errors/errors"
	prettyjson "github.com/hokaccha/go-prettyjson"
)

var debug bool
var butlerPath string
var snip = true
var verbose bool
var logSql bool
var logHttp bool
var raw bool
var profileID int64
var cliDbPath string
var execSingle string
var appName string

var ErrCycle = errors.New("cycle")

func main() {
	app := kingpin.New("cutter", "A CLI for butlerd (the butler daemon)")
	app.Arg("butler-path", "Path to butler repository").Required().StringVar(&butlerPath)
	app.Flag("verbose", "Show JSON-RPC traffic and butler log lines").BoolVar(&verbose)
	app.Flag("debug", "Show debug-level log notifications from butlerd").BoolVar(&debug)
	app.Flag("dbpath", "Explicit path for database").StringVar(&cliDbPath)
	app.Flag("appname", "Application to open the database for").Default("kitch").StringVar(&appName)
	app.Flag("profile", "Profile ID to add to requests that need one").Short('p').Default("0").Int64Var(&profileID)
	app.Flag("exec", "Execute a single command and quit").Short('e').StringVar(&execSingle)
	app.Flag("log-sql", "Log SQL queries from hades").BoolVar(&logSql)
	app.Flag("log-http", "Log HTTP requests from go-itchio").BoolVar(&logHttp)
	app.Flag("raw", "Show raw JSON-RPC messages without formatting").BoolVar(&raw)

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
	singleCtx, singleCancel := context.WithCancel(context.Background())
	defer singleCancel()
	historyFile := filepath.Join(os.TempDir(), "cutter-history")
	normalPrompt := "\033[31m»\033[0m "
	pendingPrompt := "\033[31m◴\033[0m "

	butlerdSpec := &spec.Spec{}
	readSpec := func() error {
		specPath := path.Join(butlerPath, "butlerd", "generous", "spec", "butlerd.json")

		specBytes, err := ioutil.ReadFile(specPath)
		if err != nil {
			return errors.Wrap(err, 0)
		}

		err = json.Unmarshal(specBytes, butlerdSpec)
		if err != nil {
			return errors.Wrap(err, 0)
		}
		return nil
	}

	err := readSpec()
	if err != nil {
		log.Printf("Could not read butlerd spec: %s", err.Error())
	}

	requestCompletion := func() readline.PrefixCompleterInterface {
		var items []readline.PrefixCompleterInterface
		for _, req := range butlerdSpec.Requests {
			if req.Caller == "client" {
				items = append(items, readline.PcItem(req.Method))
			}
		}

		return readline.PcItem("r", items...)
	}

	notificationCompletion := func() readline.PrefixCompleterInterface {
		var items []readline.PrefixCompleterInterface
		for _, not := range butlerdSpec.Notifications {
			items = append(items, readline.PcItem(not.Method))
		}

		return readline.PcItem("n", items...)
	}

	docCompletion := func() readline.PrefixCompleterInterface {
		var items []readline.PrefixCompleterInterface
		for _, not := range butlerdSpec.Notifications {
			items = append(items, readline.PcItem(not.Method))
		}
		for _, req := range butlerdSpec.Requests {
			items = append(items, readline.PcItem(req.Method))
		}
		for _, t := range butlerdSpec.StructTypes {
			items = append(items, readline.PcItem(t.Name))
		}
		for _, t := range butlerdSpec.EnumTypes {
			items = append(items, readline.PcItem(t.Name))
		}

		return readline.PcItem("doc", items...)
	}

	var completer = readline.NewPrefixCompleter(
		requestCompletion(),
		notificationCompletion(),
		docCompletion(),
		readline.PcItem("st"),
		readline.PcItem("p"),
		readline.PcItem("login"),
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

	type mergedLine struct {
		line []byte
		err  error
	}
	mergedLines := make(chan mergedLine, 16*1024)
	pushMergedLine := func(line []byte) {
		copied := append([]byte(nil), line...)
		mergedLines <- mergedLine{line: copied}
	}
	pushMergedErr := func(err error) {
		mergedLines <- mergedLine{err: err}
	}

	renderLogf := func(format string, args ...interface{}) {
		hang()
		log.Printf(format, args...)
		l.Refresh()
	}

	type bootstrapInfo struct {
		secret string
		addr   string
	}
	bootstrapChan := make(chan bootstrapInfo, 1)

	var readWg sync.WaitGroup

	dbPath := cliDbPath

	if dbPath == "" {
		dbPath = filepath.Join(getAppPath(appName), "db", "butler.db")
	}

	dbExists := true
	_, err = os.Stat(dbPath)
	if err != nil {
		dbExists = false
	}

	pidString := strconv.FormatInt(int64(os.Getpid()), 10)

	cmd := exec.Command("butler",
		"daemon",
		"--json",
		"--transport", "tcp",
		"--destiny-pid", pidString,
		"--dbpath", dbPath,
	)

	if logSql || logHttp {
		cmd.Env = os.Environ()
		if logSql {
			cmd.Env = append(cmd.Env, "BUTLER_SQL_DEBUG=1")
		}
		if logHttp {
			cmd.Env = append(cmd.Env, "BUTLER_HTTP_DEBUG=1")
		}
	}

	if verbose {
		log.Printf("Running: %s", strings.Join(cmd.Args, " "))
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return errors.Wrap(err, 0)
	}
	cmd.Stdout = pw

	if execSingle == "" {
		cmd.Stderr = l.Stderr()
	} else {
		cmd.Stderr = os.Stderr
	}

	go func() {
		must(cmd.Start())
		must(pw.Close())
		defer cmd.Process.Kill()
		err := cmd.Wait()
		if err != nil {
			renderLogf("butler exited with error: %s", err.Error())
		}
	}()

	readWg.Add(1)
	go func() {
		defer readWg.Done()
		s := bufio.NewScanner(pr)
		s.Buffer(make([]byte, 1024*1024), 1024*1024)
		for s.Scan() {
			pushMergedLine(s.Bytes())
		}
		if err := s.Err(); err != nil {
			pushMergedErr(err)
		}
	}()

	// conn and secret are set after bootstrap (see below)
	var conn net.Conn
	var secret string

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
	getRequest := func(reqId int64) string {
		pendingMutex.Lock()
		defer pendingMutex.Unlock()

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

	responseChans := make(map[int64]chan map[string]interface{})
	var responseMutex sync.Mutex

	registerResponseChan := func(id int64) chan map[string]interface{} {
		responseMutex.Lock()
		defer responseMutex.Unlock()
		ch := make(chan map[string]interface{}, 1)
		responseChans[id] = ch
		return ch
	}

	unregisterResponseChan := func(id int64) {
		responseMutex.Lock()
		defer responseMutex.Unlock()
		delete(responseChans, id)
	}

	getResponseChan := func(id int64) (chan map[string]interface{}, bool) {
		responseMutex.Lock()
		defer responseMutex.Unlock()
		ch, ok := responseChans[id]
		return ch, ok
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
			log.Printf("  - %s: %v", color.RedString(field.Name), color.BlueString(fmt.Sprintf("%v", field.Value)))
			log.Printf("    %s", field.Doc)
		}
	}

	requestsByMethod := make(map[string]*spec.RequestSpec)
	for _, req := range butlerdSpec.Requests {
		requestsByMethod[req.Method] = req
	}
	notificationsByMethod := make(map[string]*spec.NotificationSpec)
	for _, not := range butlerdSpec.Notifications {
		notificationsByMethod[not.Method] = not
	}
	structTypesByMethod := make(map[string]*spec.StructTypeSpec)
	for _, t := range butlerdSpec.StructTypes {
		structTypesByMethod[t.Name] = t
	}
	enumTypesByMethod := make(map[string]*spec.EnumTypeSpec)
	for _, t := range butlerdSpec.EnumTypes {
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
			log.Printf("%s", req.Doc)
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
			log.Printf("%s", not.Doc)
			log.Printf("")
			logFields("Parameters", not.Params.Fields)
			log.Printf("")
			return
		}

		if t, ok := structTypesByMethod[name]; ok {
			log.Printf("")
			log.Printf("%s (Struct)", color.GreenString(t.Name))
			log.Printf("")
			log.Printf("%s", t.Doc)
			log.Printf("")
			logFields("Fields", t.Fields)
			log.Printf("")
			return
		}

		if t, ok := enumTypesByMethod[name]; ok {
			log.Printf("")
			log.Printf("%s (Enum)", color.GreenString(t.Name))
			log.Printf("")
			log.Printf("%s", t.Doc)
			log.Printf("")
			logEnumValues("Values", t.Values)
			log.Printf("")
			return
		}

		log.Printf("No doc found for '%s'", name)
	}

	var lastMethod = ""
	var lastStack = ""
	var lastData map[string]interface{}

	type msgKind int

	const (
		msgUnknown msgKind = iota
		msgErrorResponse
		msgResultResponse
		msgServerRequest
		msgNotification
	)

	prettyResult := func(result interface{}) string {
		resultString := pretty(result)
		if !snip {
			return resultString
		}

		resultLines := strings.Split(resultString, "\n")
		if len(resultLines) > 60 {
			temp := append(resultLines[0:30], color.YellowString("..................... snip ....................."))
			temp = append(temp, resultLines[len(resultLines)-30:]...)
			resultLines = temp
		}
		return strings.Join(resultLines, "\n")
	}

	classifyMessage := func(m map[string]interface{}) msgKind {
		if _, ok := m["error"]; ok {
			return msgErrorResponse
		}
		if _, ok := m["result"]; ok {
			return msgResultResponse
		}
		if _, ok := m["id"]; ok {
			return msgServerRequest
		}
		if _, ok := m["params"]; ok {
			return msgNotification
		}
		return msgUnknown
	}

	handleResponseSideEffects := func(kind msgKind, m map[string]interface{}) string {
		if kind != msgErrorResponse && kind != msgResultResponse {
			return ""
		}

		id, ok := m["id"].(float64)
		if !ok {
			return "<Unknown request>"
		}

		reqID := int64(id)
		if ch, ok := getResponseChan(reqID); ok {
			ch <- m
		}

		return getRequest(reqID)
	}

	writeExecOutput := func(payload interface{}, line []byte) {
		if raw {
			fmt.Fprintf(os.Stdout, "%s", string(line))
		} else {
			jsonBytes, err := json.MarshalIndent(payload, "", "  ")
			if err != nil {
				panic(err)
			}
			fmt.Fprintf(os.Stdout, "%s", string(jsonBytes))
		}
		singleCancel()
	}

	renderMessage := func(kind msgKind, line []byte, m map[string]interface{}, responseMethod string) {
		if verbose {
			if raw {
				renderLogf("← %s", string(line))
			} else {
				prettyLine, err := f.Format(line)
				must(err)
				renderLogf("← %s", string(prettyLine))
			}
		}

		switch kind {
		case msgErrorResponse:
			e, ok := m["error"].(map[string]interface{})
			if !ok {
				renderLogf("\n Error we can't unwrap: %s\n", pretty(m))
				return
			}

			if data, ok := e["data"].(map[string]interface{}); ok {
				lastData = data
				if stack, ok := data["stack"].(string); ok {
					lastStack = stack
				} else {
					lastStack = ""
				}
			} else {
				lastStack = ""
			}

			if execSingle != "" {
				writeExecOutput(m["error"], line)
			} else if raw {
				renderLogf("%s", string(line))
			} else {
				renderLogf("⚠ %s (Code %d):", color.GreenString(responseMethod), int64(e["code"].(float64)))
				renderLogf("    %s", color.RedString(e["message"].(string)))
				if hasDoc(responseMethod) {
					renderLogf("(Use the 'doc' command to learn more about %s)", color.GreenString(responseMethod))
				}
				if lastStack != "" {
					renderLogf("(Use the 'st' command to see a full stack trace)")
				}
			}
			singleCancel()
		case msgResultResponse:
			// reply to one of our requests
			if responseMethod == "Meta.Authenticate" {
				return
			}

			if execSingle != "" {
				writeExecOutput(m["result"], line)
			} else if raw {
				renderLogf("%s", string(line))
			} else {
				renderLogf("← %s: %s\n", color.GreenString(responseMethod), prettyResult(m["result"]))
			}
		case msgServerRequest:
			// server request
			method := m["method"].(string)

			lastMethod = method
			if raw {
				renderLogf("%s", string(line))
			} else {
				renderLogf("→ %s: %s\n", color.GreenString(method), pretty(m["params"]))
				renderLogf("(Reply to this server request with '%.0f [json payload]')", m["id"])
				if hasDoc(method) {
					renderLogf("(Use the 'doc' command to learn more about %s)", color.GreenString(method))
				}
			}
		case msgNotification:
			// notification
			method := m["method"].(string)
			if method == "Log" {
				if p, ok := m["params"].(map[string]interface{}); ok {
					if p["level"] != "debug" || debug {
						if raw {
							renderLogf("%s", string(line))
						} else {
							renderLogf("✉ %s %s\n", p["level"], p["message"])
						}
					}
				}
				return
			}

			if execSingle != "" {
				writeExecOutput(m["params"], line)
			} else if raw {
				renderLogf("%s", string(line))
			} else {
				renderLogf("✉ %s %s\n", color.GreenString(method), prettyResult(m["params"]))
			}
		case msgUnknown:
			if raw {
				renderLogf("%s", string(line))
			} else {
				renderLogf(" Not sure what: %s\n", pretty(m))
			}
		}
	}

	go func() {
		bootstrapped := false
		for item := range mergedLines {
			if item.err != nil {
				must(item.err)
			}

			line := item.line
			if len(line) == 0 {
				continue
			}

			m := make(map[string]interface{})
			if err := json.Unmarshal(line, &m); err != nil {
				if verbose {
					renderLogf("[butler]: %s", string(line))
				}
				continue
			}

			if msgType, ok := m["type"].(string); ok {
				switch msgType {
				case "butlerd/listen-notification":
					if !bootstrapped {
						secretValue, addr, ok := parseListenNotification(m)
						if ok {
							bootstrapped = true
							bootstrapChan <- bootstrapInfo{secret: secretValue, addr: addr}
						}
					}
					continue
				case "log":
					if logSql && m["message"] == "hades query" {
						if logLine, ok := formatSQLLogLine(m); ok {
							renderLogf("%s", logLine)
						}
						continue
					}
					if logHttp && m["message"] == "http request" {
						if logLine, ok := formatHTTPLogLine(m); ok {
							renderLogf("%s", logLine)
						}
						continue
					}
				}
				if verbose {
					renderLogf("[butler]: %s", string(line))
				}
				continue
			}

			kind := classifyMessage(m)
			responseMethod := handleResponseSideEffects(kind, m)
			renderMessage(kind, line, m, responseMethod)
		}
	}()

	boot := <-bootstrapChan
	secret = boot.secret
	addr := boot.addr
	if verbose {
		log.Printf("Connecting to %s...", addr)
	}

	conn, err = net.Dial("tcp", addr)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	defer conn.Close()

	readWg.Add(1)
	go func() {
		defer readWg.Done()
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadBytes('\n')
			if err != nil && err != io.EOF {
				if strings.Contains(err.Error(), "use of closed") {
					return
				}
				pushMergedErr(err)
				return
			}

			line = bytes.TrimRight(line, "\n")
			if len(line) > 0 {
				pushMergedLine(line)
			}

			if err == io.EOF {
				pushMergedErr(errors.New("connection closed"))
				return
			}
		}
	}()

	go func() {
		readWg.Wait()
		close(mergedLines)
	}()

	var id int64

	base64UrlEncode := func(data []byte) string {
		return base64.RawURLEncoding.EncodeToString(data)
	}

	generateCodeVerifier := func() (string, error) {
		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			return "", err
		}
		return base64UrlEncode(b), nil
	}

	generateCodeChallenge := func(verifier string) string {
		h := sha256.Sum256([]byte(verifier))
		return base64UrlEncode(h[:])
	}

	sendCommand := func(line string) error {
		line = strings.TrimSpace(line)

		rootTokens := strings.SplitN(line, " ", 2)
		if len(rootTokens) != 2 {
			switch line {
			case "q", "quit", "exit":
				log.Printf("Bye!")
				os.Exit(0)
			case "ed":
				if lastData == nil {
					log.Printf("No last error data available")
				} else {
					log.Print("============================")
					log.Print("Last error data:")
					log.Print(pretty(lastData))
					log.Print("============================")
				}
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
			case "debug":
				debug = !debug
				log.Printf("Debug mode is now: %v", debug)
				return nil
			case "snip":
				snip = !snip
				log.Printf("Snip mode is now: %v", snip)
				return nil
			case "login":
				hang()
				codeVerifier, err := generateCodeVerifier()
				if err != nil {
					log.Printf("⚠ Failed to generate code verifier: %s", err.Error())
					l.Refresh()
					return nil
				}
				codeChallenge := generateCodeChallenge(codeVerifier)

				stateBytes := make([]byte, 16)
				_, err = rand.Read(stateBytes)
				if err != nil {
					log.Printf("⚠ Failed to generate state: %s", err.Error())
					l.Refresh()
					return nil
				}
				state := base64UrlEncode(stateBytes)

				clientID := "85252daf268d27fbefac93e1ac462bfd"
				redirectURI := "itch://oauth-callback"

				oauthURL := fmt.Sprintf(
					"https://itch.io/user/oauth?client_id=%s&scope=itch&redirect_uri=%s&state=%s&response_type=code&code_challenge=%s&code_challenge_method=S256",
					clientID,
					url.QueryEscape(redirectURI),
					url.QueryEscape(state),
					url.QueryEscape(codeChallenge),
				)

				log.Printf("")
				log.Printf("Open this URL in your browser to log in:")
				log.Printf("")
				log.Printf("  %s", color.BlueString(oauthURL))
				log.Printf("")
				log.Printf("After authorizing, paste the code or the full callback URL below.")
				log.Printf("")

				l.SetPrompt("Paste authorization code: ")
				l.Refresh()
				input, err := l.Readline()
				l.SetPrompt(normalPrompt)
				if err != nil {
					l.Refresh()
					return nil
				}
				input = strings.TrimSpace(input)
				if input == "" {
					log.Printf("Login cancelled.")
					l.Refresh()
					return nil
				}

				// Extract code from input - could be a raw code or a full callback URL
				code := input
				if strings.Contains(input, "://") {
					parsed, err := url.Parse(input)
					if err == nil {
						if c := parsed.Query().Get("code"); c != "" {
							code = c
						}
					}
				}

				// Send Profile.LoginWithOAuthCode request and wait for response
				loginReqID := id
				id++

				respCh := registerResponseChan(loginReqID)
				defer unregisterResponseChan(loginReqID)

				loginReq := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      loginReqID,
					"method":  "Profile.LoginWithOAuthCode",
					"params": map[string]interface{}{
						"code":         code,
						"codeVerifier": codeVerifier,
						"redirectUri":  redirectURI,
						"clientId":     clientID,
					},
				}

				loginReqBytes, err := json.Marshal(loginReq)
				if err != nil {
					log.Printf("⚠ Failed to marshal login request: %s", err.Error())
					l.Refresh()
					return nil
				}

				_, err = conn.Write(append(loginReqBytes, '\n'))
				if err != nil {
					log.Printf("⚠ Failed to send login request: %s", err.Error())
					l.Refresh()
					return nil
				}
				pushRequest(loginReqID, "Profile.LoginWithOAuthCode")

				log.Printf("Waiting for login response...")

				select {
				case resp := <-respCh:
					if errObj, ok := resp["error"]; ok {
						if e, ok := errObj.(map[string]interface{}); ok {
							log.Printf("⚠ Login failed: %s", color.RedString(e["message"].(string)))
						}
					} else if result, ok := resp["result"]; ok {
						if r, ok := result.(map[string]interface{}); ok {
							if profile, ok := r["profile"].(map[string]interface{}); ok {
								if pid, ok := profile["id"].(float64); ok {
									profileID = int64(pid)
									username := ""
									if user, ok := profile["user"].(map[string]interface{}); ok {
										if u, ok := user["username"].(string); ok {
											username = u
										}
									}
									log.Printf("Logged in as %s (profile %d)", color.GreenString(username), profileID)
								}
							}
						}
					}
				case <-time.After(30 * time.Second):
					log.Printf("⚠ Login timed out after 30 seconds")
				}
				l.Refresh()
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
				log.Printf("  %s", color.YellowString("p [id]"))
				log.Printf("    Set profileId to [id] automatically for all future requests")
				log.Printf("")
				log.Printf("  %s", color.YellowString("login"))
				log.Printf("    Authenticate with itch.io using OAuth 2.0 + PKCE")
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

		if kind == "p" {
			profileID, err = strconv.ParseInt(rest, 10, 64)
			if err != nil {
				return errors.Wrap(err, 0)
			}

			log.Print(color.YellowString(fmt.Sprintf("Switched to profile %d", profileID)))
			return nil
		}

		req := make(map[string]interface{})
		req["jsonrpc"] = "2.0"

		var payload string
		var payloadField string
		var addProfileID bool

		switch kind {
		case "r":
			payloadField = "params"
			tokens := strings.SplitN(rest, " ", 2)
			method := tokens[0]

			if rs, ok := requestsByMethod[method]; ok {
				for _, f := range rs.Params.Fields {
					if f.Name == "profileId" {
						addProfileID = true
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

		// if that request wants a 'profileId' param
		if addProfileID {
			// ... and it's not included in the payload yet
			if _, ok := payloadObj["profileId"]; !ok {
				// ... and we have one set!
				if profileID != 0 {
					// then add it
					payloadObj["profileId"] = profileID
				} else {
					// or tell the user about 'p'
					log.Printf("%s", color.RedString("You're missing a 'profileId' parameter"))
					log.Printf("You can use the %s command to set a profile ID for all requests", color.GreenString("p [id]"))
				}
			}
		}

		req[payloadField] = payloadObj

		reqBytes, err := json.Marshal(req)
		if err != nil {
			return errors.WrapPrefix(err, "while marshalling request", 0)
		}

		if verbose {
			if raw {
				log.Printf("\n→ %s\n", string(reqBytes))
			} else {
				prettyInput, err := f.Format(reqBytes)
				if err != nil {
					return errors.WrapPrefix(err, "while pretty-printing request", 0)
				}
				log.Printf("\n→ %s\n", string(prettyInput))
			}
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

	err = sendCommand(fmt.Sprintf(`r Meta.Authenticate {"secret": %q}`, secret))
	if err != nil {
		panic(err)
	}

	if execSingle != "" {
		err = sendCommand(execSingle)
		if err != nil {
			panic(err)
		}
		<-singleCtx.Done()
		os.Exit(0)
	}

	log.Printf("Thanks for flying with cutter!")
	log.Printf("Using DB (%s)", dbPath)
	if !dbExists {
		log.Printf("(Warning: This file did not exist when cutter started up!)")
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
					log.Printf("Got super early EOF, if you're on msys/cygwin you might want to call `winpty cutter` instead.")
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

func parseListenNotification(m map[string]interface{}) (secret string, addr string, ok bool) {
	secret, ok = m["secret"].(string)
	if !ok || secret == "" {
		return "", "", false
	}

	tcpBlock, ok := m["tcp"].(map[string]interface{})
	if !ok {
		return "", "", false
	}

	addr, ok = tcpBlock["address"].(string)
	if !ok || addr == "" {
		return "", "", false
	}

	return secret, addr, true
}

func formatSQLLogLine(m map[string]interface{}) (string, bool) {
	query, _ := m["query"].(string)
	if query == "" {
		return "", false
	}

	duration := ""
	if d, ok := m["duration"].(float64); ok {
		duration = time.Duration(int64(d)).String()
	}

	args, _ := m["args"].([]interface{})

	var buf bytes.Buffer
	highlighted := query
	if err := quick.Highlight(&buf, query, "sql", "terminal256", "monokai"); err == nil {
		highlighted = strings.TrimSpace(buf.String())
	}

	if len(args) > 0 {
		return fmt.Sprintf("[sql] [%s] %s %v", duration, highlighted, args), true
	}

	return fmt.Sprintf("[sql] [%s] %s", duration, highlighted), true
}

func formatHTTPLogLine(m map[string]interface{}) (string, bool) {
	method, _ := m["method"].(string)
	url, _ := m["url"].(string)
	if method == "" || url == "" {
		return "", false
	}

	statusCode := 0
	if sc, ok := m["status_code"].(float64); ok {
		statusCode = int(sc)
	}

	duration := ""
	if d, ok := m["duration_ms"].(float64); ok {
		duration = fmt.Sprintf("%dms", int64(d))
	}

	result := fmt.Sprintf("[http] [%s] %s %d %s", duration, method, statusCode, url)

	if retrying, ok := m["retrying"].(bool); ok && retrying {
		reason, _ := m["retry_reason"].(string)
		result += fmt.Sprintf(" (retrying: %s)", reason)
	}

	if errMsg, ok := m["error"].(string); ok && errMsg != "" {
		result += fmt.Sprintf(" error: %s", errMsg)
	}

	return result, true
}

func rebuild() {
	hang()
	log.Printf("Rebuilding...")
	bash := func(command string) error {
		startTime := time.Now()

		log.Print(color.HiBlueString(fmt.Sprintf("$ %s", command)))
		cmd := exec.Command("bash", "-c", command)
		cmd.Dir = butlerPath
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Print(color.RedString("Command failed, log follows:"))
			log.Print(string(out))
			return err
		}
		log.Printf("(Took %s)", time.Since(startTime))
		return nil
	}

	err := bash("go get -v ./butlerd/generous")
	if err != nil {
		log.Print(color.RedString(fmt.Sprintf("Could not build generous: %s", err.Error())))
		return
	}

	err = bash("generous godocs")
	if err != nil {
		log.Print(color.RedString(fmt.Sprintf("Could not generate spec: %s", err.Error())))
		return
	}

	err = bash("go get -v")
	if err != nil {
		log.Print(color.RedString(fmt.Sprintf("Could not build butler: %s", err.Error())))
		return
	}
}

func hang() {
	// time.Sleep(100 * time.Millisecond)
}
