package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	//"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	//"github.com/cretz/bine/control"
	"github.com/cretz/bine/process"
	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/torutil/ed25519"
	"github.com/jroimartin/gocui"
	//"github.com/mitchellh/mapstructure"
)

type OnionKey struct {
	Version3 bool
	Key      crypto.PrivateKey
	Id       string
	Name     string
}

func LoadOnionKey(path string) (*OnionKey, error) {
	ok := OnionKey{}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&ok)
	return &ok, err
}

func (ok *OnionKey) Save(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	file.Chmod(0600)
	encoder := gob.NewEncoder(file)
	encoder.Encode(ok)
	file.Close()
	return nil
}

type User struct {
	Id        string
	Name      string
	PublicKey *rsa.PublicKey
}

type ConnState int

const (
	// States to handle outgoing connections
	ConnStateOutStart ConnState = iota
	ConnStateOutWaitChallenge
	ConnStateOutWaitResult

	// States to handle incoming connections
	ConnStateInStart
	ConnStateInWaitResponse

	ConnStateVerified
)

type Conn struct {
	Raw   *net.Conn
	Buf   *bufio.ReadWriter
	Token string
	State ConnState
}

type ConnInfo struct {
	Id       string
	ConnChan chan *net.Conn
}

type Chat struct {
	Ready       bool
	Conn        Conn
	SendMsgChan chan interface{}
	Num         int
	User        User
	Console     bool
	Buffer      []string
	OriginX     int
	OriginY     int
	CursorX     int
	CursorY     int
}

func NewChat(user User) Chat {
	return Chat{User: user, Conn: Conn{}, SendMsgChan: make(chan interface{}, 8)}
}

type Chats struct {
	chats  []*Chat
	byId   map[string]*Chat
	byName map[string]*Chat
	lock   sync.RWMutex
}

func NewChats() *Chats {
	ch := Chats{
		chats:  make([]*Chat, 0),
		byId:   make(map[string]*Chat),
		byName: make(map[string]*Chat),
	}
	return &ch
}

func (ch *Chats) Add(chat *Chat) {
	ch.lock.Lock()
	defer ch.lock.Unlock()
	ch.chats = append(ch.chats, chat)
	ch.byId[chat.User.Id] = chat
	ch.byName[chat.User.Name] = chat
	chat.Num = len(ch.chats)
}

func (ch *Chats) ById(id string) *Chat {
	ch.lock.RLock()
	defer ch.lock.RUnlock()
	if chat, ok := ch.byId[id]; ok {
		return chat
	} else {
		return nil
	}
}

type MsgType string

const (
	MsgTypeHello     = "hello"
	MsgTypeChallenge = "challenge"
	MsgTypeResponse  = "response"
	MsgTypeResult    = "result"
	MsgTypeText      = "text"
)

type MsgBodyHello struct {
	Id        string        `json:"id"`
	PublicKey rsa.PublicKey `json:"pk"`
}

type MsgBodyChallenge struct {
	Token string `json:"token"`
}

type MsgBodyResponse struct {
	Signature []byte `json:"sig"`
}

type Result string

const (
	ResultAccept = "accept"
	ResultReject = "reject"
)

type MsgBodyResult struct {
	Result Result `json:"result"`
}

type MsgBodyText struct {
	Text string `json:"text"`
}

type Msg struct {
	Id      string          `json:"-"`
	Type    string          `json:"type"`
	RawBody json.RawMessage `json:"body"`
	Body    interface{}     `json:"-"`
}

func (m *Msg) MarshalJSON() ([]byte, error) {
	m.RawBody, _ = json.Marshal(m.Body)
	switch body := m.Body.(type) {
	case *MsgBodyHello:
		m.Type = MsgTypeHello
	case *MsgBodyChallenge:
		m.Type = MsgTypeChallenge
	case *MsgBodyResponse:
		m.Type = MsgTypeResponse
	case *MsgBodyResult:
		m.Type = MsgTypeResult
	case *MsgBodyText:
		m.Type = MsgTypeText
	default:
		return nil, fmt.Errorf("Invalid Body Type for Msg: %T", body)
	}
	type Alias Msg
	return json.Marshal(&struct{ *Alias }{Alias: (*Alias)(m)})
}

func (m *Msg) UnmarshalJSON(data []byte) error {
	type Alias Msg
	if err := json.Unmarshal(data, &struct{ *Alias }{Alias: (*Alias)(m)}); err != nil {
		return err
	}
	var body interface{}
	switch m.Type {
	case MsgTypeHello:
		body = &MsgBodyHello{}
	case MsgTypeChallenge:
		body = &MsgBodyChallenge{}
	case MsgTypeResponse:
		body = &MsgBodyResponse{}
	case MsgTypeResult:
		body = &MsgBodyResult{}
	case MsgTypeText:
		body = &MsgBodyText{}
	default:
		return fmt.Errorf("Invalid Body Type for Msg: %v", m.Type)
	}
	if err := json.Unmarshal(m.RawBody, body); err == nil {
		m.Body = body
	} else {
		return fmt.Errorf("Error unmarshaling message body: %v", err)
	}
	return nil
}

// Global variables
var sendMsgChan chan string
var recvMsgChan chan Msg
var cmdChan chan string
var refreshLayoutChan chan bool
var newChatChan chan User
var onionConnectChan chan ConnInfo
var chats *Chats

var currentChat *Chat
var torProcess *tor.Tor
var torReadyCancel *context.CancelFunc
var onionListenCancel *context.CancelFunc
var onion *tor.OnionService
var onionKey *OnionKey

func switchCurrentChat(v *gocui.View, chat *Chat) {
	if currentChat == chat {
		return
	}
	// Save Current user buffer state
	currentChat.Buffer = v.BufferLines()
	// Remove last line because it's empty
	if l := len(currentChat.Buffer); l > 0 {
		currentChat.Buffer = currentChat.Buffer[:l-1]
	}
	currentChat.OriginX, currentChat.OriginY = v.Origin()
	currentChat.CursorX, currentChat.CursorY = v.Cursor()

	// Restore switched user buffer state
	currentChat = chat
	v.Clear()
	v.SetCursor(0, 0)
	for _, line := range currentChat.Buffer {
		v.Write([]byte(fmt.Sprintf("%s", line)))
		v.Write([]byte("\n"))
	}
	v.SetOrigin(currentChat.OriginX, currentChat.OriginY)
	v.SetCursor(currentChat.CursorX, currentChat.CursorY)
	refreshLayoutChan <- true
}

func setName(v *gocui.View, name string, id string) {
	// FIXME: Make this thread-safe
	if id == "" || id == onionKey.Id {
		onionKey.Name = name
		go onionKey.Save("key.gob")
	} else {
		chat := chats.ById(id)
		if chat == nil {
			logMsg("ERR", "No chat with ID %s", id)
			return
		}
		chat.User.Name = name
	}
	refreshLayoutChan <- true
}

var Editor gocui.Editor = gocui.EditorFunc(simpleEditor)

func simpleEditor(v *gocui.View, key gocui.Key, ch rune, mod gocui.Modifier) {
	switch {
	case ch != 0 && mod == 0:
		v.EditWrite(ch)
	case key == gocui.KeySpace:
		v.EditWrite(' ')
	case key == gocui.KeyBackspace || key == gocui.KeyBackspace2:
		v.EditDelete(true)
	case key == gocui.KeyArrowLeft:
		v.MoveCursor(-1, 0, false)
	case key == gocui.KeyArrowRight:
		v.MoveCursor(1, 0, false)
	case key == gocui.KeyHome:
		v.SetCursor(0, 0)
	case key == gocui.KeyEnd:
		v.SetCursor(len(v.Buffer())-1, 0)
	case key == gocui.KeyEnter:
		msg := v.Buffer()
		if len(msg) < 1 {
			return
		}
		sendMsgChan <- msg[:len(msg)-1]
		v.Clear()
		v.SetCursor(0, 0)
	}
}

func quit(g *gocui.Gui, v *gocui.View) error {
	if onion != nil {
		go onion.Close()
		time.Sleep(200 * time.Millisecond)
	}
	if onionListenCancel != nil {
		go (*onionListenCancel)()
		time.Sleep(300 * time.Millisecond)
	}
	if torProcess != nil {
		go torProcess.Close()
		time.Sleep(200 * time.Millisecond)
	}
	if torReadyCancel != nil {
		go (*torReadyCancel)()
		time.Sleep(200 * time.Millisecond)
	}
	return gocui.ErrQuit
}

func layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if v, err := g.SetView("messages", 0, 0, maxX-1, maxY-4); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Autoscroll = true
		v.Wrap = true
	}
	v, _ := g.View("messages")
	v.Title = fmt.Sprintf("%2d. %s (%s)", currentChat.Num, currentChat.User.Name, currentChat.User.Id)
	if v, err := g.SetView("readline", 0, maxY-3, maxX-1, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		if _, err := g.SetCurrentView("readline"); err != nil {
			return err
		}
		v.Editable = true
		v.Editor = Editor
		v.Wrap = false
	}
	v, _ = g.View("readline")
	v.Title = fmt.Sprintf("%s (%s)", onionKey.Name, onionKey.Id)
	return nil
}

func parseCmd(g *gocui.Gui, cmd string) error {
	args := strings.Fields(cmd[1:])
	if len(args) < 1 {
		return nil
	}
	var buffer bytes.Buffer
	switch args[0] {
	case "help":
		buffer.WriteString("Available commands:\n")
		buffer.WriteString("    /help           : Shows this help\n")
		buffer.WriteString("    /chat NAME      : Switch to NAME chat\n")
		buffer.WriteString("    /list           : Shows list of chats\n")
		buffer.WriteString("    /name NAME [ID] : Set your NAME or ID's NAME\n")
		buffer.WriteString("    /new  NAME ID   : Switch to NAME chat\n")
		buffer.WriteString("    /quit           : Quit program\n")
	case "chat":
		if len(args) < 2 {
			buffer.WriteString("Usage: \"/chat NAME\"")
			break
		}
		chat, ok := chats.byName[args[1]]
		if !ok {
			buffer.WriteString(fmt.Sprintf("No chat found with name \"%s\"", args[1]))
			break
		}
		v, _ := g.View("messages")
		switchCurrentChat(v, chat)
	case "list":
		buffer.WriteString("List of chats:\n")
		for i, chat := range chats.chats {
			ready := ""
			if !chat.Ready {
				ready = "connecting..."
			}
			buffer.WriteString(fmt.Sprintf("    %2d. %s (%s) %s\n", i+1, chat.User.Name, chat.User.Id, ready))
		}
	case "name":
		if len(args) < 2 {
			buffer.WriteString("Usage: \"/name NAME [ID]\"")
			break
		}
		v, _ := g.View("readline")
		id := ""
		if len(args) > 2 {
			id = args[2]
		}
		setName(v, args[1], id)
	case "new":
		if len(args) < 3 {
			buffer.WriteString("Usage: \"/new NAME ID\"")
			break
		}
		newChatChan <- User{Name: args[1], Id: args[2]}
	case "quit":
		return gocui.ErrQuit
	default:
		buffer.WriteString(fmt.Sprintf(
			"Unknown command: \"%s\".  Use /help to see available commands", cmd))
	}
	if buffer.Len() > 0 {
		recvMsgChan <- Msg{Id: "-", Type: MsgTypeText, Body: &MsgBodyText{Text: buffer.String()}}
	}
	return nil
}

func genToken() string {
	var token = make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(token)
}

func printMsg(v *gocui.View, chat *Chat, name, msg string) {
	t := time.Now()
	line := fmt.Sprintf("%s %s: %s", t.Format("15:04:05"), name, msg)
	if chat == nil || chat == currentChat {
		v.Write([]byte(line))
		v.Write([]byte("\n"))
	} else {
		chat.Buffer = append(chat.Buffer, line)
	}
}

func recvMsg(v *gocui.View, msg *Msg) {
	chat := chats.ById(msg.Id)
	if chat != nil {
		body, ok := msg.Body.(*MsgBodyText)
		if ok {
			printMsg(v, chat, chat.User.Name, body.Text)
		}
	} // else {
	//		printMsg(v, nil, "msg.Id", "No chat found")
	//	}
}

func logMsg(namespace string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	recvMsgChan <- Msg{Id: "-", Type: MsgTypeText, Body: &MsgBodyText{fmt.Sprintf("[%s] %s", namespace, msg)}}
}

type logTorMsg struct {
	kind string
}

func (l *logTorMsg) Write(p []byte) (int, error) {
	// We strip the trailing '\n'
	for _, line := range strings.Split(string(p[:len(p)-1]), "\n") {
		// We also strip the timestamp because printMsg already handles that
		msg := string(line[len("Sep 09 22:04:23.544 "):])
		logMsg(fmt.Sprintf("Tor - %s", l.kind), msg)
	}
	return len(p), nil
}

type torProcessCreator struct{}

func (t *torProcessCreator) New(ctx context.Context, args ...string) (process.Process, error) {
	cmd := exec.CommandContext(ctx, "tor", args...)
	cmd.Stdout = &logTorMsg{kind: "sdtout"}
	cmd.Stderr = &logTorMsg{kind: "stderr"}
	return cmd, nil
}

func startOnion() {
	var err error

	newKey := false
	if _, err := os.Stat("key.gob"); os.IsNotExist(err) {
		newKey = true
		onionKey = &OnionKey{}
	} else {
		onionKey, err = LoadOnionKey("key.gob")
		if err != nil {
			logMsg("Tor - ERR", "Unable to load onion service key key.gob: %v", err)
			return
		} else {
			logMsg("Tor", "Loaded onion service key with ID: %v", onionKey.Id)
			logMsg("Tor - DBG", "key: %+v", onionKey.Key)
		}
		refreshLayoutChan <- true
	}

	torProcess, err = tor.Start(nil,
		&tor.StartConf{DataDir: "data", ProcessCreator: &torProcessCreator{}, TorrcFile: "torrc"})
	if err != nil {
		logMsg("Tor - ERR", "Unable to start Tor: %v", err)
		return
	}
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	torReadyCancel = &readyCancel
	defer readyCancel()
	if err := torProcess.EnableNetwork(readyCtx, true); err != nil {
		logMsg("Tor - ERR", "Unable to connect to Tor Network: %v", err)
		return
	}

	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	onionListenCancel = &listenCancel
	defer listenCancel()
	if newKey {
		logMsg("Tor", "Generating new Onion Service key...")
	}
	logMsg("Tor", "Registering Onion Service.  This can take some time...")
	onion, err = torProcess.Listen(listenCtx, &tor.ListenConf{RemotePorts: []int{6060}, Key: onionKey.Key, Version3: onionKey.Version3})
	if err != nil {
		logMsg("Tor - ERR", "Unable to create onion service: %v", err)
		return
	}
	logMsg("Tor", "Successfully registered Onion Service with ID: %v", onion.ID)
	if newKey {
		onionKey.Version3, onionKey.Key, onionKey.Id = onion.Version3, onion.Key.(*rsa.PrivateKey), onion.ID
		if err := onionKey.Save("key.gob"); err != nil {
			logMsg("Tor - ERR", "Unable save the onion service key as key.gob: %v", err)
			return
		} else {
			logMsg("Tor", "Stored the onion service key as key.gob")
			logMsg("Tor - DBG", "key: %+v", onionKey.Key)
			logMsg("Tor - DBG", "key: %+v", onionKey.Key.(*rsa.PrivateKey))
		}
		refreshLayoutChan <- true
	}

	go onionConnectLoop(torProcess)
	go onionAcceptLoop(onion)
	go newChatLoop()
}

func onionAcceptLoop(onion *tor.OnionService) {
	for {
		conn, err := onion.Accept()
		if err != nil {
			logMsg("Tor - ERR", "Error accepting onion connections: %v", err)
			return
		}
		logMsg("Tor - DBG", "Accepted new onion connections")
		go handleInConnection(conn)
	}
}

func handleInConnection(conn net.Conn) {
	bufConRead := bufio.NewReader(conn)
	bufConWrite := bufio.NewWriter(conn)
	bufConn := bufio.NewReadWriter(bufConRead, bufConWrite)

	chat := NewChat(User{})
	chat.Conn.State = ConnStateInStart
	chat.Conn.Raw = &conn
	chat.Conn.Buf = bufConn
	go func() {
		if err := setupChat(&chat); err != nil {
			logMsg("Tor - ERR", "%v", err)
			conn.Close()
		}
	}()
}

func newChatLoop() {
	for {
		user := <-newChatChan
		chat := NewChat(user)
		chats.Add(&chat)
		go handleNewChat(&chat)
	}
}

func handleNewChat(chat *Chat) {
	if err := setOutConn(chat); err != nil {
		return
	}

	chat.Conn.State = ConnStateOutStart
	go setupChat(chat)
}

func handleChat(chat *Chat) {
	// handle incoming messages
	go func() {
		for {
			m, err := readMsg(chat.Conn.Buf)
			if err != nil {
				continue
			}
			m.Id = chat.User.Id
			switch m.Type {
			case "text":
				recvMsgChan <- *m
			}
		}
	}()
	// handle outgoing messages
	go func() {
		for {
			body := <-chat.SendMsgChan
			if err := sendMsg(chat.Conn.Buf, body); err != nil {
				logMsg("Tor - ERR", "Error sending message to %s: %v", chat.User.Id, err)
			}
		}
	}()
}

func readMsg(bufConn *bufio.ReadWriter) (*Msg, error) {
	mJson, err := bufConn.ReadBytes('\n')
	if err != nil {
		logMsg("Tor - ERR", "Error receiving message: %v", err)
		return nil, err
	}
	mJson = mJson[:len(mJson)-1] // Strip the trailing '\n'
	logMsg("Tor - DBG", "Received message: %v", string(mJson))
	var m Msg
	err = json.Unmarshal(mJson, &m)
	if err != nil {
		logMsg("Tor - ERR", "Error unmarshaling message: %v", err)
		return nil, err
	}
	return &m, nil
}

func sendMsg(bufConn *bufio.ReadWriter, body interface{}) error {
	mJson, _ := json.Marshal(&Msg{Body: body})
	_, err := bufConn.Write(mJson)
	if err != nil {
		logMsg("Tor - ERR", "Error sending message: %v", err)
		return err
	}
	_, err = bufConn.Write([]byte("\n"))
	if err != nil {
		logMsg("Tor - ERR", "Error sending message: %v", err)
		return err
	}
	bufConn.Flush()
	logMsg("Tor - DBG", "Sent message: %v", string(mJson))
	return nil
}

func setOutConn(chat *Chat) error {
	connChan := make(chan *net.Conn)
	onionConnectChan <- ConnInfo{Id: chat.User.Id, ConnChan: connChan}
	conn := <-connChan
	if conn == nil {
		logMsg("Tor - ERR", "Unable to stablish outgoing connection with %s", chat.User.Id)
		return fmt.Errorf("Unable to stablish outgoing connection")
	}
	logMsg("Tor - DBG", "Established new onion connections with %s", chat.User.Id)
	bufConRead := bufio.NewReader(*conn)
	bufConWrite := bufio.NewWriter(*conn)
	bufConn := bufio.NewReadWriter(bufConRead, bufConWrite)
	chat.Conn.Raw = conn
	chat.Conn.Buf = bufConn
	return nil
}

func setupChat(chat *Chat) error {
	var msgSendBody interface{}
	var msgRecvd *Msg
	var err error
	for {
		msgSendBody = nil
		// Read incomming message
		if chat.Conn.State != ConnStateOutStart && chat.Conn.State != ConnStateVerified {
			if msgRecvd, err = readMsg(chat.Conn.Buf); err != nil {
				return fmt.Errorf("Error reading messag in connection with %s: %v", chat.User.Id, err)
			}
		}

		switch chat.Conn.State {
		case ConnStateOutStart:
			msgSendBody = &MsgBodyHello{Id: onionKey.Id, PublicKey: onionKey.Key.(*rsa.PrivateKey).PublicKey}
			chat.Conn.State = ConnStateOutWaitChallenge
			logMsg("Tor - DBG", "Waiting for challenge...")
		case ConnStateOutWaitChallenge:
			if body, ok := msgRecvd.Body.(*MsgBodyChallenge); ok {
				chat.Conn.Token = body.Token
				msg := []byte(fmt.Sprintf("gonion-response:%s:%s", chat.User.Id, chat.Conn.Token))
				hashed := sha256.Sum256(msg)

				if sig, err := rsa.SignPKCS1v15(rand.Reader, onionKey.Key.(*rsa.PrivateKey),
					crypto.SHA256, hashed[:]); err != nil {
					return fmt.Errorf("Signing error: %s\n", err)
				} else {
					msgSendBody = &MsgBodyResponse{Signature: sig}
				}
				chat.Conn.State = ConnStateOutWaitResult
				logMsg("Tor - DBG", "Waiting for accept...")
			}
		case ConnStateOutWaitResult:
			if body, ok := msgRecvd.Body.(*MsgBodyResult); ok {
				if body.Result == ResultAccept {
					chat.Conn.State = ConnStateVerified
				} else {
					return fmt.Errorf("Challenge response was rejected in connection with %s", chat.User.Id)
				}
			}
		case ConnStateInStart:
			if body, ok := msgRecvd.Body.(*MsgBodyHello); !ok {
				return fmt.Errorf("Unexpected message type %T in connection with %s", msgRecvd.Body, chat.User.Id)
			} else {
				if body.Id == onionKey.Id {
					return fmt.Errorf("Received a hello message with our ID.  Skipping...")
				}
				chat.User.Id = body.Id
				chat.User.PublicKey = &body.PublicKey
				chats.Add(chat)
				chat.Conn.Token = genToken()
				msgSendBody = &MsgBodyChallenge{Token: chat.Conn.Token}
				chat.Conn.State = ConnStateInWaitResponse
				logMsg("Tor - DBG", "Waiting for challenge response...")
			}
		case ConnStateInWaitResponse:
			msg := []byte(fmt.Sprintf("gonion-response:%s:%s", onionKey.Id, chat.Conn.Token))
			hashed := sha256.Sum256(msg)
			if body, ok := msgRecvd.Body.(*MsgBodyResponse); ok {
				if err := rsa.VerifyPKCS1v15(chat.User.PublicKey, crypto.SHA256, hashed[:], body.Signature); err != nil {
					msgSendBody = &MsgBodyResult{Result: ResultReject}
					return fmt.Errorf("Invalid signature as challenge response in connection with %s", chat.User.Id)
				} else {
					msgSendBody = &MsgBodyResult{Result: ResultAccept}
					chat.Conn.State = ConnStateVerified
				}
			}
		case ConnStateVerified:
			logMsg("Tor - DBG", "Connection with %s has been verified and is ready for chatting.", chat.User.Id)
			chat.Ready = true
			handleChat(chat)
			return nil
		}

		// Send reply message
		if msgSendBody != nil {
			if err := sendMsg(chat.Conn.Buf, msgSendBody); err != nil {
				return fmt.Errorf("Unable to setup outgoing connection with %s: %v", chat.User.Id, err)
			}
		}
	}
}

func onionConnectLoop(torProcess *tor.Tor) {
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer readyCancel()
	torDialer, err := torProcess.Dialer(readyCtx, nil)
	if err != nil {
		logMsg("Tor - ERR", "Unable establish Tor connections: %v", err)
	}
	for {
		connInfo := <-onionConnectChan
		conn, err := torDialer.Dial("tcp", fmt.Sprintf("%s.onion:6060", connInfo.Id))
		if err != nil {
			logMsg("Tor - ERR", "Error connecting to %s: %v", connInfo.Id, err)
			connInfo.ConnChan <- nil
		} else {
			logMsg("Tor", "Connected to: (%v)", connInfo.Id)
			connInfo.ConnChan <- &conn
		}
	}
}

func eventLoop(g *gocui.Gui) {
	for {
		select {
		case msg := <-sendMsgChan:
			g.Update(func(g *gocui.Gui) (err error) {
				v, _ := g.View("messages")
				if msg[0] == '/' {
					printMsg(v, chats.chats[0], onionKey.Name, msg)
					err = parseCmd(g, msg)
				} else {
					if currentChat.Ready {
						currentChat.SendMsgChan <- &MsgBodyText{Text: msg}
						printMsg(v, nil, onionKey.Name, msg)
					}
				}
				return err
			})
		case msg := <-recvMsgChan:
			g.Update(func(g *gocui.Gui) error {
				v, _ := g.View("messages")
				recvMsg(v, &msg)
				return nil
			})
		case <-refreshLayoutChan:
			g.Update(func(g *gocui.Gui) error {
				layout(g)
				return nil
			})
		}
	}
}

func main() {
	//// Initialization
	// Register types used as interface{} for gob serialization and deserializatin
	gob.Register(&rsa.PrivateKey{})
	gob.Register(ed25519.PrivateKey{})

	sendMsgChan = make(chan string, 8)
	recvMsgChan = make(chan Msg, 8)
	cmdChan = make(chan string, 8)
	refreshLayoutChan = make(chan bool, 8)
	newChatChan = make(chan User, 8)
	onionConnectChan = make(chan ConnInfo, 8)

	onionKey = &OnionKey{Version3: false}

	chats = NewChats()

	chats.Add(&Chat{Ready: true, User: User{Id: "-", Name: "console"}, Console: true})
	currentChat = chats.chats[0]

	if _, err := os.Stat("data"); os.IsNotExist(err) {
		err := os.Mkdir("data", 0700)
		if err != nil {
			panic(err)
		}
	}

	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		log.Panicln(err)
	}

	g.Cursor = true

	g.SetManagerFunc(layout)

	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		log.Panicln(err)
	}

	for i := 0; i < 9; i++ {
		chatIdx := i
		if err := g.SetKeybinding("", rune('1'+i), gocui.ModAlt,
			func(g *gocui.Gui, _ *gocui.View) error {
				if chatIdx >= len(chats.chats) {
					return nil
				}
				v, _ := g.View("messages")
				chat := chats.chats[chatIdx]
				switchCurrentChat(v, chat)
				return nil
			}); err != nil {
			log.Panicln(err)
		}
	}

	go eventLoop(g)
	go startOnion()

	if err := g.MainLoop(); err != nil && err != gocui.ErrQuit {
		log.Panicln(err)
	}

	g.Close()
}
