package rpc

import (
	"bufio"
	"fmt"
	"github.com/hashicorp/logutils"
	"github.com/ugorji/go/codec"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

var (
	clientClosed = fmt.Errorf("client closed")
)

const (
	MinIPCVersion = 1
	MaxIPCVersion = 1
)

const (
	handshakeCommand  = "handshake"
	eventCommand      = "event"
	forceLeaveCommand = "force-leave"
	joinCommand       = "join"
	membersCommand    = "members"
	streamCommand     = "stream"
	stopCommand       = "stop"
	monitorCommand    = "monitor"
	leaveCommand      = "leave"
)

// Request header is sent before each request
type requestHeader struct {
	Command string
	Seq     uint64
}

// Response header is sent before each response
type responseHeader struct {
	Seq   uint64
	Error string
}

type handshakeRequest struct {
	Version int32
}

type eventRequest struct {
	Name     string
	Payload  []byte
	Coalesce bool
}

type forceLeaveRequest struct {
	Node string
}

type joinRequest struct {
	Existing []string
	Replay   bool
}

type joinResponse struct {
	Num int32
}

type membersResponse struct {
	Members []Member
}

type monitorRequest struct {
	LogLevel string
}

type streamRequest struct {
	Type string
}

type stopRequest struct {
	Stop uint64
}

type logRecord struct {
	Log string
}

type Member struct {
	Name        string
	Addr        net.IP
	Port        uint16
	Role        string
	Status      string
	ProtocolMin uint8
	ProtocolMax uint8
	ProtocolCur uint8
	DelegateMin uint8
	DelegateMax uint8
	DelegateCur uint8
}

type seqCallback struct {
	handler func(*responseHeader)
}

func (sc *seqCallback) Handle(resp *responseHeader) {
	sc.handler(resp)
}
func (sc *seqCallback) Cleanup() {}

// seqHandler interface is used to handle responses
type seqHandler interface {
	Handle(*responseHeader)
	Cleanup()
}

// Client is the RPC client to make requests to the agent RPC.
type Client struct {
	seq uint64

	conn      *net.TCPConn
	reader    *bufio.Reader
	writer    *bufio.Writer
	dec       *codec.Decoder
	enc       *codec.Encoder
	writeLock sync.Mutex

	dispatch     map[uint64]seqHandler
	dispatchLock sync.Mutex

	shutdown     bool
	shutdownCh   chan struct{}
	shutdownLock sync.Mutex
}

// send is used to send an object using the MsgPack encoding. send
// is serialized to prevent write overlaps, while properly buffering.
func (c *Client) send(header *requestHeader, obj interface{}) error {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	if c.shutdown {
		return clientClosed
	}

	if err := c.enc.Encode(header); err != nil {
		return err
	}

	if obj != nil {
		if err := c.enc.Encode(obj); err != nil {
			return err
		}
	}

	if err := c.writer.Flush(); err != nil {
		return err
	}

	return nil
}

// NewClient is used to create a new RPC client given the address.
// This will properly dial, handshake, and start listening
func NewClient(addr string) (*Client, error) {
	// Try to dial to serf
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Create the client
	client := &Client{
		seq:        0,
		conn:       conn.(*net.TCPConn),
		reader:     bufio.NewReader(conn),
		writer:     bufio.NewWriter(conn),
		dispatch:   make(map[uint64]seqHandler),
		shutdownCh: make(chan struct{}),
	}
	client.dec = codec.NewDecoder(client.reader,
		&codec.MsgpackHandle{RawToString: true, WriteExt: true})
	client.enc = codec.NewEncoder(client.writer,
		&codec.MsgpackHandle{RawToString: true, WriteExt: true})
	go client.listen()

	// Do the initial handshake
	if err := client.handshake(); err != nil {
		client.Close()
		return nil, err
	}
	return client, err
}

// StreamHandle is an opaque handle passed to stop to stop streaming
type StreamHandle uint64

// Close is used to free any resources associated with the client
func (c *Client) Close() error {
	c.shutdownLock.Lock()
	defer c.shutdownLock.Unlock()

	if !c.shutdown {
		c.shutdown = true
		close(c.shutdownCh)
		c.deregisterAll()
		return c.conn.Close()
	}
	return nil
}

// ForceLeave is used to ask the agent to issue a leave command for
// a given node
func (c *Client) ForceLeave(node string) error {
	header := requestHeader{
		Command: forceLeaveCommand,
		Seq:     c.getSeq(),
	}
	req := forceLeaveRequest{
		Node: node,
	}
	return c.genericRPC(&header, &req, nil)
}

// Join is used to instruct the agent to attempt a join
func (c *Client) Join(addrs []string, replay bool) (int, error) {
	header := requestHeader{
		Command: joinCommand,
		Seq:     c.getSeq(),
	}
	req := joinRequest{
		Existing: addrs,
		Replay:   replay,
	}
	var resp joinResponse

	err := c.genericRPC(&header, &req, &resp)
	return int(resp.Num), err
}

// Members is used to fetch a list of known members
func (c *Client) Members() ([]Member, error) {
	header := requestHeader{
		Command: membersCommand,
		Seq:     c.getSeq(),
	}
	var resp membersResponse

	err := c.genericRPC(&header, nil, &resp)
	return resp.Members, err
}

// UserEvent is used to trigger sending an event
func (c *Client) UserEvent(name string, payload []byte, coalesce bool) error {
	header := requestHeader{
		Command: eventCommand,
		Seq:     c.getSeq(),
	}
	req := eventRequest{
		Name:     name,
		Payload:  payload,
		Coalesce: coalesce,
	}
	return c.genericRPC(&header, &req, nil)
}

// Leave is used to trigger a graceful leave and shutdown
func (c *Client) Leave() error {
	header := requestHeader{
		Command: leaveCommand,
		Seq:     c.getSeq(),
	}
	return c.genericRPC(&header, nil, nil)
}

type monitorHandler struct {
	client *Client
	closed bool
	init   bool
	initCh chan<- error
	logCh  chan<- string
	seq    uint64
}

func (mh *monitorHandler) Handle(resp *responseHeader) {
	// Initialize on the first response
	if !mh.init {
		mh.init = true
		mh.initCh <- strToError(resp.Error)
		return
	}

	// Decode logs for all other responses
	var rec logRecord
	if err := mh.client.dec.Decode(&rec); err != nil {
		log.Printf("[ERR] Failed to decode log: %v", err)
		mh.client.deregisterHandler(mh.seq)
		return
	}
	select {
	case mh.logCh <- rec.Log:
	default:
		log.Printf("[ERR] Dropping log! Monitor channel full")
	}
}

func (mh *monitorHandler) Cleanup() {
	if !mh.closed {
		if !mh.init {
			mh.init = true
			mh.initCh <- fmt.Errorf("Stream closed")
		}
		close(mh.logCh)
		mh.closed = true
	}
}

// Monitor is used to subscribe to the logs of the agent
func (c *Client) Monitor(level logutils.LogLevel, ch chan<- string) (StreamHandle, error) {
	// Setup the request
	seq := c.getSeq()
	header := requestHeader{
		Command: monitorCommand,
		Seq:     seq,
	}
	req := monitorRequest{
		LogLevel: string(level),
	}

	// Create a monitor handler
	initCh := make(chan error, 1)
	handler := &monitorHandler{
		client: c,
		initCh: initCh,
		logCh:  ch,
		seq:    seq,
	}
	c.handleSeq(seq, handler)

	// Send the request
	if err := c.send(&header, &req); err != nil {
		c.deregisterHandler(seq)
		return 0, err
	}

	// Wait for a response
	select {
	case err := <-initCh:
		return StreamHandle(seq), err
	case <-c.shutdownCh:
		c.deregisterHandler(seq)
		return 0, clientClosed
	}
}

type streamHandler struct {
	client  *Client
	closed  bool
	init    bool
	initCh  chan<- error
	eventCh chan<- map[string]interface{}
	seq     uint64
}

func (sh *streamHandler) Handle(resp *responseHeader) {
	// Initialize on the first response
	if !sh.init {
		sh.init = true
		sh.initCh <- strToError(resp.Error)
		return
	}

	// Decode logs for all other responses
	var rec map[string]interface{}
	if err := sh.client.dec.Decode(&rec); err != nil {
		log.Printf("[ERR] Failed to decode stream record: %v", err)
		sh.client.deregisterHandler(sh.seq)
		return
	}
	select {
	case sh.eventCh <- rec:
	default:
		log.Printf("[ERR] Dropping event! Stream channel full")
	}
}

func (sh *streamHandler) Cleanup() {
	if !sh.closed {
		if !sh.init {
			sh.init = true
			sh.initCh <- fmt.Errorf("Stream closed")
		}
		close(sh.eventCh)
		sh.closed = true
	}
}

// Stream is used to subscribe to events
func (c *Client) Stream(filter string, ch chan<- map[string]interface{}) (StreamHandle, error) {
	// Setup the request
	seq := c.getSeq()
	header := requestHeader{
		Command: streamCommand,
		Seq:     seq,
	}
	req := streamRequest{
		Type: filter,
	}

	// Create a monitor handler
	initCh := make(chan error, 1)
	handler := &streamHandler{
		client:  c,
		initCh:  initCh,
		eventCh: ch,
		seq:     seq,
	}
	c.handleSeq(seq, handler)

	// Send the request
	if err := c.send(&header, &req); err != nil {
		c.deregisterHandler(seq)
		return 0, err
	}

	// Wait for a response
	select {
	case err := <-initCh:
		return StreamHandle(seq), err
	case <-c.shutdownCh:
		c.deregisterHandler(seq)
		return 0, clientClosed
	}
}

// Stop is used to unsubscribe from logs or event streams
func (c *Client) Stop(handle StreamHandle) error {
	// Deregister locally first to stop delivery
	c.deregisterHandler(uint64(handle))

	header := requestHeader{
		Command: stopCommand,
		Seq:     c.getSeq(),
	}
	req := stopRequest{
		Stop: uint64(handle),
	}
	return c.genericRPC(&header, &req, nil)
}

// handshake is used to perform the initial handshake on connect
func (c *Client) handshake() error {
	header := requestHeader{
		Command: handshakeCommand,
		Seq:     c.getSeq(),
	}
	req := handshakeRequest{
		Version: MaxIPCVersion,
	}
	return c.genericRPC(&header, &req, nil)
}

// genericRPC is used to send a request and wait for an
// errorSequenceResponse, potentially returning an error
func (c *Client) genericRPC(header *requestHeader, req interface{}, resp interface{}) error {
	// Setup a response handler
	errCh := make(chan error, 1)
	handler := func(respHeader *responseHeader) {
		if resp != nil {
			err := c.dec.Decode(resp)
			if err != nil {
				errCh <- err
				return
			}
		}
		errCh <- strToError(respHeader.Error)
	}
	c.handleSeq(header.Seq, &seqCallback{handler: handler})
	defer c.deregisterHandler(header.Seq)

	// Send the request
	if err := c.send(header, req); err != nil {
		return err
	}

	// Wait for a response
	select {
	case err := <-errCh:
		return err
	case <-c.shutdownCh:
		return clientClosed
	}
}

// strToError converts a string to an error if not blank
func strToError(s string) error {
	if s != "" {
		return fmt.Errorf(s)
	}
	return nil
}

// getSeq returns the next sequence number in a safe manner
func (c *Client) getSeq() uint64 {
	return atomic.AddUint64(&c.seq, 1)
}

// deregisterAll is used to deregister all handlers
func (c *Client) deregisterAll() {
	c.dispatchLock.Lock()
	defer c.dispatchLock.Unlock()

	for _, seqH := range c.dispatch {
		seqH.Cleanup()
	}
	c.dispatch = make(map[uint64]seqHandler)
}

// deregisterHandler is used to deregister a handler
func (c *Client) deregisterHandler(seq uint64) {
	c.dispatchLock.Lock()
	seqH, ok := c.dispatch[seq]
	delete(c.dispatch, seq)
	c.dispatchLock.Unlock()

	if ok {
		seqH.Cleanup()
	}
}

// handleSeq is used to setup a handlerto wait on a response for
// a given sequence number.
func (c *Client) handleSeq(seq uint64, handler seqHandler) {
	c.dispatchLock.Lock()
	defer c.dispatchLock.Unlock()
	c.dispatch[seq] = handler
}

// respondSeq is used to respond to a given sequence number
func (c *Client) respondSeq(seq uint64, respHeader *responseHeader) {
	c.dispatchLock.Lock()
	seqL, ok := c.dispatch[seq]
	c.dispatchLock.Unlock()

	// Get a registered listener, ignore if none
	if ok {
		seqL.Handle(respHeader)
	}
}

// listen is used to processes data coming over the IPC channel,
// and wrote it to the correct destination based on seq no
func (c *Client) listen() {
	defer c.Close()
	var respHeader responseHeader
	for {
		if err := c.dec.Decode(&respHeader); err != nil {
			if !c.shutdown {
				log.Printf("[ERR] agent.client: Failed to decode response header: %v", err)
			}
			break
		}
		c.respondSeq(respHeader.Seq, &respHeader)
	}
}
