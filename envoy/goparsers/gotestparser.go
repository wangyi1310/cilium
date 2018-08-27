package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/envoy/cilium"

	log "github.com/sirupsen/logrus"
)

type PasserParserFactory struct{}

func init() {
	log.Info("init(): Registering PasserParserFactory")
	RegisterParserFactory("passer", &PasserParserFactory{})
}

type PasserParser struct{}

func (p *PasserParserFactory) Create(connection *Connection) Parser {
	// Reject invalid policy name for testing purposes
	if connection.PolicyName == "invalid-policy" {
		return nil
	}

	log.Infof("PasserParserFactory: Create: %v", connection)
	return &PasserParser{}
}

//
// This simply passes all data in either direction.
//
func (p *PasserParser) OnData(reply, endStream bool, data []string, offset uint32) (FilterOpType, uint32) {
	n_bytes := uint32(0)
	for _, s := range data {
		n_bytes += uint32(len(s)) - offset
		offset = 0
	}
	if n_bytes == 0 {
		return FILTEROP_NOP, 0
	}
	if !reply {
		log.Infof("PasserParser: Request: %d bytes", n_bytes)
	} else {
		log.Infof("PasserParser: Response: %d bytes", n_bytes)
	}
	return FILTEROP_PASS, n_bytes
}

//
// Line parser used for testing
//

type LineParserFactory struct{}

var lineParserFactory *LineParserFactory

func init() {
	log.Info("init(): Registering lineParserFactory")
	RegisterParserFactory("linetester", lineParserFactory)
}

type LineParser struct {
	connection *Connection
	inserted   bool
}

func (p *LineParserFactory) Create(connection *Connection) Parser {
	log.Infof("LineParserFactory: Create: %v", connection)
	return &LineParser{connection: connection}
}

func getLine(data []string, offset uint32) (string, bool) {
	var line string
	for _, s := range data {
		index := strings.IndexByte(s[offset:], '\n')
		if index < 0 {
			line += s[offset:]
		} else {
			line += s[offset : offset+uint32(index)+1]
			return line, true
		}
		offset = 0
	}
	return line, false
}

//
// Parses individual lines that must start with one of:
// "PASS" the line is passed
// "DROP" the line is dropped
// "INJECT" the line is injected in reverse direction
// "INSERT" the line is injected in current direction
//
func (p *LineParser) OnData(reply, endStream bool, data []string, offset uint32) (FilterOpType, uint32) {
	line, ok := getLine(data, offset)
	line_len := uint32(len(line))

	if p.inserted {
		p.inserted = false
		return FILTEROP_DROP, line_len
	}

	if !reply {
		log.Infof("LineParser: Request: %s", line)
	} else {
		log.Infof("LineParser: Response: %s", line)
	}

	if !ok {
		if line_len > 0 {
			// Partial line received, but no newline, ask for more
			return FILTEROP_MORE, 1
		} else {
			// Nothing received, don't know if more will be coming; do nothing
			return FILTEROP_NOP, 0
		}
	}

	if strings.HasPrefix(line, "PASS") {
		return FILTEROP_PASS, line_len
	}
	if strings.HasPrefix(line, "DROP") {
		return FILTEROP_DROP, line_len
	}
	if strings.HasPrefix(line, "INJECT") {
		// Inject line in the reverse direction
		p.connection.Inject(!reply, []byte(line))
		// Drop the INJECT line in the current direction
		return FILTEROP_DROP, line_len
	}
	if strings.HasPrefix(line, "INSERT") {
		// Inject the line in the current direction
		p.connection.Inject(reply, []byte(line))
		// Drop the INJECT line in the current direction
		p.inserted = true
		return FILTEROP_INJECT, line_len
	}

	return FILTEROP_ERROR, uint32(FILTEROP_ERROR_INVALID_FRAME_TYPE)
}

//
// Block parser used for testing
//

type BlockParserFactory struct{}

var blockParserFactory *BlockParserFactory

func init() {
	log.Info("init(): Registering blockParserFactory")
	RegisterParserFactory("blocktester", blockParserFactory)
}

type BlockParser struct {
	connection *Connection
	inserted   bool
}

func (p *BlockParserFactory) Create(connection *Connection) Parser {
	log.Infof("BlockParserFactory: Create: %v", connection)
	return &BlockParser{connection: connection}
}

func getBlock(data []string, offset uint32) (string, uint32, uint32, error) {
	var block string

	block_len := uint32(0)
	have_length := false
	missing := uint32(0)

	for _, s := range data {
		if !have_length {
			index := strings.IndexByte(s[offset:], ':')
			if index < 0 {
				block += s[offset:]
				if len(block) > 0 {
					missing = 1 // require at least one more if something was received
				}
			} else {
				block += s[offset : offset+uint32(index)]
				offset += uint32(index)

				// Now 'block' contains everything before the ':', parse it as a decimal number
				// indicating the length of the frame AFTER the ':'
				len64, err := strconv.ParseUint(block, 10, 64)
				if err != nil {
					return block, 0, 0, err
				}
				block_len = uint32(len64)
				if block_len <= uint32(len(block)) {
					return block, 0, 0, fmt.Errorf("Block length too short")
				}
				have_length = true
				missing = block_len - uint32(len(block))
			}
		}
		if have_length {
			s_len := uint32(len(s)) - offset

			if missing <= s_len {
				block += s[offset : offset+missing]
				return block, block_len, 0, nil
			} else {
				block += s[offset:]
				missing -= s_len
			}
		}
		offset = 0
	}

	return block, block_len, missing, nil
}

//
// Parses individual blocks that must start with one of:
// "PASS" the block is passed
// "DROP" the block is dropped
// "INJECT" the block is injected in reverse direction
// "INSERT" the block is injected in current direction
//
func (p *BlockParser) OnData(reply, endStream bool, data []string, offset uint32) (FilterOpType, uint32) {
	block, block_len, missing, err := getBlock(data, offset)
	if err != nil {
		log.WithError(err).Warnf("BlockParser: Invalid frame length")
		return FILTEROP_ERROR, uint32(FILTEROP_ERROR_INVALID_FRAME_LENGTH)
	}

	if p.inserted {
		p.inserted = false
		return FILTEROP_DROP, block_len
	}

	if !reply {
		log.Infof("BlockParser: Request: %s", block)
	} else {
		log.Infof("BlockParser: Response: %s", block)
	}

	if missing == 0 && block_len == 0 {
		// Nothing received, don't know if more will be coming; do nothing
		return FILTEROP_NOP, 0
	}

	log.Infof("BlockParser: missing: %d", missing)

	if strings.Contains(block, "PASS") {
		p.connection.Log(cilium.EntryType_Request, &cilium.LogEntry_Http{&cilium.HttpLogEntry{Status: 200}})
		return FILTEROP_PASS, block_len
	}
	if strings.Contains(block, "DROP") {
		p.connection.Log(cilium.EntryType_Denied, &cilium.LogEntry_Http{&cilium.HttpLogEntry{Status: 201}})
		return FILTEROP_DROP, block_len
	}

	if missing > 0 {
		// Partial block received, ask for more
		return FILTEROP_MORE, missing
	}

	if strings.Contains(block, "INJECT") {
		// Inject block in the reverse direction
		p.connection.Inject(!reply, []byte(block))
		// Drop the INJECT block in the current direction
		return FILTEROP_DROP, block_len
	}
	if strings.Contains(block, "INSERT") {
		// Inject the block in the current direction
		p.connection.Inject(reply, []byte(block))
		// Drop the INJECT block in the current direction
		p.inserted = true
		return FILTEROP_INJECT, block_len
	}

	return FILTEROP_ERROR, uint32(FILTEROP_ERROR_INVALID_FRAME_TYPE)
}

//
// Header parser used for testing
//

type HeaderRule struct {
	name  string
	value string
}

func (rule *HeaderRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'
	items := strings.SplitN(data.(string), "=", 2)
	matches := len(items) == 2 && items[0] == rule.name && strings.HasPrefix(items[1], rule.value)

	if matches {
		log.Infof("HeaderRule: Rule matches %v", rule)
	} else {
		log.Infof("HeaderRule: Rule does not match %v", rule)
	}

	return matches
}

// L7HeaderRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func L7HeaderRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	httpRules := rule.GetHttpRules()
	if httpRules == nil {
		panic(fmt.Errorf("Can't get HTTP rules."))
	}
	var rules []L7NetworkPolicyRule
	for _, httpRule := range httpRules.HttpRules {
		for _, header := range httpRule.GetHeaders() {
			headerRule := HeaderRule{
				name:  header.Name,
				value: header.GetExactMatch(),
			}
			if headerRule.value == "" {
				panic(fmt.Errorf("Empty header value"))
			}
			rules = append(rules, &headerRule)
		}
	}
	log.Infof("Parsed HeaderRules: %v", rules)
	return rules
}

type HeaderParserFactory struct{}

var headerParserFactory *HeaderParserFactory

func init() {
	log.Info("init(): Registering headerParserFactory")
	RegisterParserFactory("headertester", headerParserFactory)
	RegisterL7RuleParser("PortNetworkPolicyRule_HttpRules", L7HeaderRuleParser)
}

type HeaderParser struct {
	connection *Connection
}

func (p *HeaderParserFactory) Create(connection *Connection) Parser {
	log.Infof("HeaderParserFactory: Create: %v", connection)
	return &HeaderParser{connection: connection}
}

//
// Parses individual lines that must start with one of:
// "PASS" the line is passed
// "DROP" the line is dropped
// "INJECT" the line is injected in reverse direction
// "INSERT" the line is injected in current direction
//
func (p *HeaderParser) OnData(reply, endStream bool, data []string, offset uint32) (FilterOpType, uint32) {
	line, ok := getLine(data, offset)
	line_len := uint32(len(line))

	if !reply {
		log.Infof("HeaderParser: Request: %s", line)
	} else {
		log.Infof("HeaderParser: Response: %s", line)
	}

	if !ok {
		if line_len > 0 {
			// Partial line received, but no newline, ask for more
			return FILTEROP_MORE, 1
		} else {
			// Nothing received, don't know if more will be coming; do nothing
			return FILTEROP_NOP, 0
		}
	}

	// Replies pass unconditionally
	if reply || p.connection.Matches(line) {
		p.connection.Log(cilium.EntryType_Request, &cilium.LogEntry_Http{&cilium.HttpLogEntry{Status: 200}})
		return FILTEROP_PASS, line_len
	}

	// Inject Error response to the reverse direction
	p.connection.Inject(!reply, []byte(fmt.Sprintf("Line dropped: %s", line)))
	// Drop the line in the current direction
	p.connection.Log(cilium.EntryType_Denied, &cilium.LogEntry_Http{&cilium.HttpLogEntry{Status: 403}})
	return FILTEROP_DROP, line_len
}