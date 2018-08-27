package main

/*
#include <stdint.h>

typedef enum {
  FILTEROP_MORE,   // Need more data
  FILTEROP_PASS,   // Pass N bytes
  FILTEROP_DROP,   // Drop N bytes
  FILTEROP_INJECT, // Inject N>0 bytes
  FILTEROP_ERROR,  // Protocol parsing error
} FilterOpType;

typedef enum {
  FILTEROP_ERROR_INVALID_OP_LENGTH = 1,   // Parser returned invalid operation length
  FILTEROP_ERROR_INVALID_FRAME_TYPE,
  FILTEROP_ERROR_INVALID_FRAME_LENGTH,
} FilterOpError;

typedef struct {
  uint32_t op;      // FilterOpType
  uint32_t n_bytes; // >0
} FilterOp;

typedef enum {
  FILTER_OK,                 // Operation was successful
  FILTER_POLICY_DROP,        // Connection needs to be dropped due to (L3/L4) policy
  FILTER_PARSER_ERROR,       // Connection needs to be dropped due to parser error
  FILTER_UNKNOWN_PARSER,     // Connection needs to be dropped due to unknown parser
  FILTER_UNKNOWN_CONNECTION, // Connection needs to be dropped due to it being unknown
  FILTER_INVALID_ADDRESS,    // Destination address in invalid format
} FilterResult;
*/
import "C"

import (
	"net"
	"strconv"
	"time"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/lock"

	log "github.com/sirupsen/logrus"
)

// Mirror C types to be able to use them in other Go files and tests.

type FilterOpType uint32
type FilterOpError uint32
type FilterOp struct {
	op      uint32
	n_bytes uint32
}

const (
	FILTEROP_MORE   FilterOpType = C.FILTEROP_MORE
	FILTEROP_PASS   FilterOpType = C.FILTEROP_PASS
	FILTEROP_DROP   FilterOpType = C.FILTEROP_DROP
	FILTEROP_INJECT FilterOpType = C.FILTEROP_INJECT
	FILTEROP_ERROR  FilterOpType = C.FILTEROP_ERROR
	// Internal types not exposed to Caller
	FILTEROP_NOP FilterOpType = 256

	FILTEROP_ERROR_INVALID_OP_LENGTH    FilterOpError = C.FILTEROP_ERROR_INVALID_OP_LENGTH
	FILTEROP_ERROR_INVALID_FRAME_TYPE   FilterOpError = C.FILTEROP_ERROR_INVALID_FRAME_TYPE
	FILTEROP_ERROR_INVALID_FRAME_LENGTH FilterOpError = C.FILTEROP_ERROR_INVALID_FRAME_LENGTH
)

func (op FilterOpType) String() string {
	switch op {
	case FILTEROP_MORE:
		return "MORE"
	case FILTEROP_PASS:
		return "PASS"
	case FILTEROP_DROP:
		return "DROP"
	case FILTEROP_INJECT:
		return "INJECT"
	case FILTEROP_ERROR:
		return "ERROR"
	case FILTEROP_NOP:
		return "NOP"
	}
	return "UNKNOWN_OP"
}

func (opErr FilterOpError) String() string {
	switch opErr {
	case FILTEROP_ERROR_INVALID_OP_LENGTH:
		return "ERROR_INVALID_OP_LENGTH"
	case FILTEROP_ERROR_INVALID_FRAME_TYPE:
		return "ERROR_INVALID_FRAME_TYPE"
	case FILTEROP_ERROR_INVALID_FRAME_LENGTH:
		return "ERROR_INVALID_FRAME_LENGTH"
	}
	return "UNKNOWN_OP_ERROR"
}

type FilterResult int

const (
	FILTER_OK                 FilterResult = C.FILTER_OK
	FILTER_POLICY_DROP        FilterResult = C.FILTER_POLICY_DROP
	FILTER_PARSER_ERROR       FilterResult = C.FILTER_PARSER_ERROR
	FILTER_UNKNOWN_PARSER     FilterResult = C.FILTER_UNKNOWN_PARSER
	FILTER_UNKNOWN_CONNECTION FilterResult = C.FILTER_UNKNOWN_CONNECTION
	FILTER_INVALID_ADDRESS    FilterResult = C.FILTER_INVALID_ADDRESS
)

func (r FilterResult) String() string {
	switch r {
	case FILTER_OK:
		return "OK"
	case FILTER_POLICY_DROP:
		return "POLICY_DROP"
	case FILTER_PARSER_ERROR:
		return "PARSER_ERROR"
	case FILTER_UNKNOWN_PARSER:
		return "UNKNOWN_PARSER"
	case FILTER_UNKNOWN_CONNECTION:
		return "UNKNOWN_CONNECTION"
	case FILTER_INVALID_ADDRESS:
		return "FILTER_INVALID_ADDRESS"
	}
	return "UNKNOWN_ERROR"
}

// Filter sees data from the underlying stream in both directions
// (original, connection open direction and the opposite, the reply
// direction). Each call to the filter returns an ordered set of
// operations to be performed on the data in that direction. Any data
// left over after the returned operations must be buffered by the
// caller and passed in again when more data has been received on the
// connection.

type Direction struct {
	injectBuf *[]byte
}

type Connection struct {
	Id         uint64
	Ingress    bool
	SrcId      uint32
	DstId      uint32
	SrcAddr    string
	DstAddr    string
	PolicyName string
	Port       uint32

	parser Parser
	orig   Direction
	reply  Direction
}

var mutex lock.Mutex
var connections map[uint64]*Connection

// A parser instance is used for each connection. OnData will be called from a single thread only.
type Parser interface {
	OnData(reply, endStream bool, data []string, offset uint32) (FilterOpType, uint32)
}

type ParserFactory interface {
	Create(connection *Connection) Parser // must be thread safe!
}

var parserFactories map[string]ParserFactory // const after initialization

func init() {
	log.Info("init(): Initializing go_filter")
	connections = make(map[uint64]*Connection)
}

// RegisterParserFactory adds a protocol parser factory to the map of known parsers.
// This is called from parser init() functions while we are still single-threaded
func RegisterParserFactory(name string, parserFactory ParserFactory) {
	if parserFactories == nil { // init on first call
		parserFactories = make(map[string]ParserFactory)
	}
	log.Infof("RegisterParserFactory: Registering: %v", name)
	parserFactories[name] = parserFactory
}

var policyMap PolicyMap

func (connection *Connection) Matches(l7 interface{}) bool {
	log.Infof("Matching policy on connection %v", connection)
	return policyMap.Matches(connection.PolicyName, connection.Ingress, connection.Port, connection.SrcId, l7)
}

// getInjectBuf return the pointer to the inject buffer slice header for the indicated direction
func (connection *Connection) getInjectBuf(reply bool) *[]byte {
	if reply {
		return connection.reply.injectBuf
	}
	return connection.orig.injectBuf
}

// inject buffers data to be injected into the connection at the point of FILTEROP_INJECT
func (connection *Connection) Inject(reply bool, data []byte) int {
	buf := connection.getInjectBuf(reply)
	// append data to C-provided buffer
	offset := len(*buf)
	n := copy((*buf)[offset:cap(*buf)], data)
	*buf = (*buf)[:offset+n] // update the buffer length

	log.Infof("Connection.Inject(): Injected: %d bytes: %v (given: %s)", n, string((*buf)[offset:offset+n]), data)

	// return the number of bytes injected. This may be less than the length of `data` is
	// the buffer becomes full.
	// Parser may opt dropping the connection via parser error in this case!
	return n
}

// isInjectBufFull return true if the inject buffer for the indicated direction is full
func (connection *Connection) isInjectBufFull(reply bool) bool {
	buf := connection.getInjectBuf(reply)
	return len(*buf) == cap(*buf)
}

// onData gets all the unparsed data the datapath has received so far. The data is provided to the parser
// associated with the connection, and the parser is expected to find if the data frame contains enough data
// to make a PASS/DROP decision for the whole data frame. Note that the whole data frame need not be received,
// if the decision including the length of the data frame in bytes can be determined based on the beginning of
// the data frame only (e.g., headers including the length of the data frame). The parser returns a decision
// with the number of bytes on which the decision applies. If more data is available, then the parser will be
// called again with the remaining data. Parser needs to return FILTEROP_MORE if a decision can't be made with
// the available data, including the minimum number of additional bytes that is needed before the parser is
// called again.
//
// The parser can also inject at arbitrary points in the data stream. This is indecated by an INJECT operation
// with the number of bytes to be injected. The actual bytes to be injected are provided via an Inject()
// callback prior to returning the INJECT operation. The Inject() callback operates on a limited size buffer
// provided by the datapath, and multiple INJECT operations may be needed to inject large amounts of data.
// Since we get the data on one direction at a time, any frames to be injected in the reverse direction
// are placed in the reverse direction buffer, from where the datapath injects the data before calling
// us again for the reverse direction input.
func (connection *Connection) onData(reply, endStream bool, data *[]string, filterOps *[]FilterOp) FilterResult {
	unit := 0
	offset := uint32(0)

	// Loop until `filterOps` becomes full, or parser is done with the data.
	for len(*filterOps) < cap(*filterOps) {
		op, bytes := connection.parser.OnData(reply, endStream, (*data)[unit:], offset)
		if op == FILTEROP_NOP {
			break // No operations after NOP
		}
		if bytes == 0 {
			return FILTER_PARSER_ERROR
		}
		*filterOps = append(*filterOps, FilterOp{uint32(op), bytes})

		if op == FILTEROP_MORE {
			// Need more data before can parse ahead.
			// Parser will see the unused data again in the next call, which will take place
			// after there are at least 'bytes' of additional data to parse.
			break
		}

		if op == FILTEROP_PASS || op == FILTEROP_DROP {
			// Skip bytes in input, or exhaust the input.
			for bytes > 0 && unit < len(*data) {
				rem := uint32(len((*data)[unit])) - offset // this much data left in unit
				if bytes < rem {                           // more than 'bytes' bytes in unit
					offset += bytes
					bytes = 0
				} else { // go to the beginning of the next unit
					bytes -= rem
					unit++
					offset = 0
				}
			}
			// Loop back to parser even if have no more data to allow the parser to
			// inject frames at the end of the input.
		}

		// Injection does not advance input data, but instructs the datapath to
		// send data the parser has placed in the inject buffer. We need to stop processing
		// if inject buffer becomes full as the parser in this case can't inject any more
		// data.
		if op == FILTEROP_INJECT && connection.isInjectBufFull(reply) {
			// return if inject buffer becomes full
			break
		}
	}
	return FILTER_OK
}

func (conn *Connection) Log(entryType cilium.EntryType, l7 interface{}) {
	pblog := &cilium.LogEntry{
		Timestamp:             uint64(time.Now().UnixNano()),
		IsIngress:             conn.Ingress,
		EntryType:             entryType,
		PolicyName:            conn.PolicyName,
		SourceSecurityId:      conn.SrcId,
		DestinationSecurityId: conn.DstId,
		SourceAddress:         conn.SrcAddr,
		DestinationAddress:    conn.DstAddr,
		L7:                    cilium.IsL7(l7),
	}
	accessLogClient.Log(pblog)
}

//export OnNewConnection
func OnNewConnection(proto string, connectionId uint64, ingress bool, srcId, dstId uint32, srcAddr, dstAddr, policyName string, origBuf, replyBuf *[]byte) FilterResult {
	// Find the parser for the proto
	parserFactory := parserFactories[proto]
	if parserFactory == nil {
		return FILTER_UNKNOWN_PARSER
	}
	_, port, err := net.SplitHostPort(dstAddr)
	if err != nil {
		return FILTER_INVALID_ADDRESS
	}
	dstPort, err := strconv.ParseUint(port, 10, 32)
	if err != nil || dstPort == 0 {
		return FILTER_INVALID_ADDRESS
	}
	connection := &Connection{
		Id:         connectionId,
		Ingress:    ingress,
		SrcId:      srcId,
		DstId:      dstId,
		SrcAddr:    srcAddr,
		DstAddr:    dstAddr,
		Port:       uint32(dstPort),
		PolicyName: policyName,
		orig:       Direction{injectBuf: origBuf},
		reply:      Direction{injectBuf: replyBuf},
	}
	connection.parser = parserFactory.Create(connection)
	if connection.parser == nil {
		// Parser rejected the new connection based on the connection metadata
		return FILTER_POLICY_DROP
	}

	mutex.Lock()
	connections[connectionId] = connection
	mutex.Unlock()

	return FILTER_OK
}

// Each connection is assumed to be called from a single thread, so accessing connection metadata
// does not need protection.
//export OnData
func OnData(connectionId uint64, reply, endStream bool, data *[]string, filterOps *[]FilterOp) FilterResult {
	// Find the connection
	mutex.Lock()
	connection, ok := connections[connectionId]
	mutex.Unlock()
	if !ok {
		return FILTER_UNKNOWN_CONNECTION
	}
	return connection.onData(reply, endStream, data, filterOps)
}

// Make this more general connection event callback
//export Close
func Close(connectionId uint64) {
	mutex.Lock()
	delete(connections, connectionId)
	mutex.Unlock()
}

// called before any other APIs
//export InitModule
func InitModule(accessLogPath string) bool {
	policyMap = NewPolicyMap()
	return startAccessLogClient(accessLogPath)
}

// Must have empty main
func main() {}