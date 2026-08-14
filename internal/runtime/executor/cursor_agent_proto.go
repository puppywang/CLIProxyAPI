package executor

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// Connect-RPC streaming flags. Captured from cursor-agent 2026.08.11
// (agent.v1.AgentService/Run, application/connect+proto).
const (
	cursorConnectFlagGzip = 0x01
	cursorConnectFlagEnd  = 0x02
	cursorAgentModeAgent  = 1
	cursorPBValueMaxDepth = 32
)

type pbField struct {
	Num  uint64
	Wire uint8
	Data []byte
}

func pbAppendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func pbFieldLD(field uint64, data []byte) []byte {
	out := pbAppendVarint(nil, field<<3|2)
	out = pbAppendVarint(out, uint64(len(data)))
	return append(out, data...)
}

func pbFieldStr(field uint64, s string) []byte {
	return pbFieldLD(field, []byte(s))
}

func pbFieldVarint(field uint64, v uint64) []byte {
	out := pbAppendVarint(nil, field<<3)
	return pbAppendVarint(out, v)
}

func pbIter(buf []byte) []pbField {
	var out []pbField
	for len(buf) > 0 {
		tag, n := pbReadVarint(buf)
		if n <= 0 {
			break
		}
		buf = buf[n:]
		num := tag >> 3
		wire := uint8(tag & 7)
		switch wire {
		case 0:
			_, n = pbReadVarint(buf)
			if n <= 0 {
				return out
			}
			out = append(out, pbField{Num: num, Wire: wire, Data: buf[:n]})
			buf = buf[n:]
		case 1:
			if len(buf) < 8 {
				return out
			}
			out = append(out, pbField{Num: num, Wire: wire, Data: buf[:8]})
			buf = buf[8:]
		case 2:
			ln, n := pbReadVarint(buf)
			if n <= 0 {
				return out
			}
			buf = buf[n:]
			if uint64(len(buf)) < ln {
				return out
			}
			out = append(out, pbField{Num: num, Wire: wire, Data: buf[:ln]})
			buf = buf[ln:]
		case 5:
			if len(buf) < 4 {
				return out
			}
			out = append(out, pbField{Num: num, Wire: wire, Data: buf[:4]})
			buf = buf[4:]
		default:
			return out
		}
	}
	return out
}

func pbReadVarint(buf []byte) (uint64, int) {
	var v uint64
	var s uint
	for i, b := range buf {
		if i == 10 {
			return 0, 0
		}
		v |= uint64(b&0x7f) << s
		if b < 0x80 {
			return v, i + 1
		}
		s += 7
	}
	return 0, 0
}

func pbVarintValue(data []byte) uint64 {
	v, _ := pbReadVarint(data)
	return v
}

func pbFirst(fields []pbField, num uint64) (pbField, bool) {
	for _, f := range fields {
		if f.Num == num {
			return f, true
		}
	}
	return pbField{}, false
}

func pbFirstStr(fields []pbField, num uint64) string {
	f, ok := pbFirst(fields, num)
	if !ok || f.Wire != 2 {
		return ""
	}
	return string(f.Data)
}

func pbFirstLD(fields []pbField, num uint64) []byte {
	f, ok := pbFirst(fields, num)
	if !ok || f.Wire != 2 {
		return nil
	}
	return f.Data
}

// pbFirstMessage preserves presence for an explicitly encoded empty message.
// A protobuf oneof may legally contain a zero-length message, so a nil byte
// slice alone cannot distinguish "present but empty" from "not present".
func pbFirstMessage(fields []pbField, num uint64) ([]byte, bool) {
	f, ok := pbFirst(fields, num)
	if !ok || f.Wire != 2 {
		return nil, false
	}
	return f.Data, true
}

func cursorConnectHeartbeatFrame() []byte {
	// AgentClientMessage.client_heartbeat = 7, empty ClientHeartbeat.
	return cursorEncodeConnectFrame(0, pbFieldLD(7, nil))
}

func cursorGunzipIfNeeded(flags byte, payload []byte) ([]byte, error) {
	if flags&cursorConnectFlagGzip == 0 {
		return payload, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(r)
}

func cursorEncodeJSONValue(raw json.RawMessage, depth int) []byte {
	if depth > cursorPBValueMaxDepth {
		return pbFieldVarint(1, 0)
	}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return pbFieldVarint(1, 0)
	}
	switch gjson.ParseBytes(raw).Type {
	case gjson.False:
		return pbFieldVarint(4, 0)
	case gjson.True:
		return pbFieldVarint(4, 1)
	case gjson.Number:
		n, _ := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
		return cursorPBDouble(2, n)
	case gjson.String:
		return pbFieldStr(3, gjson.ParseBytes(raw).String())
	case gjson.JSON:
		parsed := gjson.ParseBytes(raw)
		if parsed.IsArray() {
			var list []byte
			for _, item := range parsed.Array() {
				list = append(list, pbFieldLD(1, cursorEncodeJSONValue(json.RawMessage(item.Raw), depth+1))...)
			}
			return pbFieldLD(6, list)
		}
		if parsed.IsObject() {
			var fields []byte
			parsed.ForEach(func(k, v gjson.Result) bool {
				entry := pbFieldStr(1, k.String())
				entry = append(entry, pbFieldLD(2, cursorEncodeJSONValue(json.RawMessage(v.Raw), depth+1))...)
				fields = append(fields, pbFieldLD(1, entry)...)
				return true
			})
			return pbFieldLD(5, fields)
		}
	}
	return pbFieldVarint(1, 0)
}

func cursorPBDouble(field uint64, v float64) []byte {
	out := pbAppendVarint(nil, field<<3|1)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], math.Float64bits(v))
	return append(out, buf[:]...)
}

func cursorDecodeJSONValue(data []byte, depth int) json.RawMessage {
	if depth > cursorPBValueMaxDepth {
		return json.RawMessage("null")
	}
	fields := pbIter(data)
	if f, ok := pbFirst(fields, 1); ok && f.Wire == 0 {
		return json.RawMessage("null")
	}
	if f, ok := pbFirst(fields, 2); ok && f.Wire == 1 && len(f.Data) == 8 {
		n := math.Float64frombits(binary.LittleEndian.Uint64(f.Data))
		return json.RawMessage(strconv.FormatFloat(n, 'f', -1, 64))
	}
	if f, ok := pbFirst(fields, 3); ok && f.Wire == 2 {
		b, _ := json.Marshal(string(f.Data))
		return b
	}
	if f, ok := pbFirst(fields, 4); ok && f.Wire == 0 {
		if pbVarintValue(f.Data) != 0 {
			return json.RawMessage("true")
		}
		return json.RawMessage("false")
	}
	if f, ok := pbFirst(fields, 5); ok && f.Wire == 2 {
		obj := map[string]json.RawMessage{}
		for _, entry := range pbIter(f.Data) {
			if entry.Num != 1 || entry.Wire != 2 {
				continue
			}
			ef := pbIter(entry.Data)
			key := pbFirstStr(ef, 1)
			val := pbFirstLD(ef, 2)
			obj[key] = cursorDecodeJSONValue(val, depth+1)
		}
		b, _ := json.Marshal(obj)
		return b
	}
	if f, ok := pbFirst(fields, 6); ok && f.Wire == 2 {
		var arr []json.RawMessage
		for _, item := range pbIter(f.Data) {
			if item.Num == 1 && item.Wire == 2 {
				arr = append(arr, cursorDecodeJSONValue(item.Data, depth+1))
			}
		}
		b, _ := json.Marshal(arr)
		return b
	}
	return json.RawMessage("null")
}

func cursorEncodeMcpTool(tool cursorClientTool, provider string) []byte {
	_ = provider // retained in the helper signature for compatibility with callers
	name := tool.Name
	out := pbFieldStr(1, name)
	if tool.Description != "" {
		out = append(out, pbFieldStr(3, tool.Description)...)
	}
	schema := tool.Parameters
	if len(bytes.TrimSpace(schema)) == 0 {
		schema = json.RawMessage(`{"type":"object"}`)
	}
	// The official CLI constructs input_schema as google.protobuf.Struct
	// (agent.v1.McpToolDescriptor field 4), not as the legacy JSON-string
	// fallback field. Keep the wire shape identical to cursor-agent.
	out = append(out, pbFieldLD(4, cursorEncodeStruct(schema))...)
	return out
}

func cursorEncodeStruct(raw json.RawMessage) []byte {
	parsed := gjson.ParseBytes(raw)
	if !parsed.IsObject() {
		return nil
	}
	var out []byte
	parsed.ForEach(func(key, value gjson.Result) bool {
		entry := pbFieldStr(1, key.String())
		entry = append(entry, pbFieldLD(2, cursorEncodeJSONValue(json.RawMessage(value.Raw), 0))...)
		out = append(out, pbFieldLD(1, entry)...)
		return true
	})
	return out
}

func cursorEncodeMcpTools(tools []cursorClientTool) []byte {
	var out []byte
	for _, t := range tools {
		if strings.TrimSpace(t.Name) == "" {
			continue
		}
		out = append(out, pbFieldLD(1, cursorEncodeMcpTool(t, "cpa"))...)
	}
	return out
}

func cursorEncodeModelMeta(modelID string, params []cursorModelParam) []byte {
	out := pbFieldStr(1, modelID)
	for _, p := range params {
		kv := pbFieldStr(1, p.ID)
		kv = append(kv, pbFieldStr(2, p.Value)...)
		out = append(out, pbFieldLD(3, kv)...)
	}
	return out
}

func cursorEncodeModelDetails(modelID string) []byte {
	// ModelDetails carries the selected model plus the display identifiers the
	// official CLI sends. For a CPA model alias there is no separate display
	// name, so the canonical model id is the safest value for all four fields.
	out := pbFieldStr(1, modelID)
	out = append(out, pbFieldStr(3, modelID)...)
	out = append(out, pbFieldStr(4, modelID)...)
	out = append(out, pbFieldStr(5, modelID)...)
	out = append(out, pbFieldStr(6, modelID)...)
	return out
}

func cursorEncodeRunRequest(prompt, modelID, convID, msgID, runID string, params []cursorModelParam, tools []cursorClientTool) []byte {
	inner := pbFieldStr(1, prompt)
	inner = append(inner, pbFieldStr(2, msgID)...)
	inner = append(inner, pbFieldVarint(4, cursorAgentModeAgent)...)
	action := pbFieldLD(2, pbFieldLD(1, pbFieldLD(1, inner)))

	// AgentRunRequest.conversation_state is a message. An empty state is a
	// valid minimal request; workspace/context replay is deliberately handled
	// by the local CPA tool bridge rather than by undocumented extra frames.
	req := pbFieldLD(1, nil)
	req = append(req, action...)
	req = append(req, pbFieldLD(3, cursorEncodeModelDetails(modelID))...)
	req = append(req, pbFieldLD(4, cursorEncodeMcpTools(tools))...)
	req = append(req, pbFieldStr(5, convID)...)
	req = append(req, pbFieldLD(9, cursorEncodeModelMeta(modelID, params))...)
	// AgentRunRequest.run_id is present in the official CLI request and is also
	// used as the logical request identity for reconnect/telemetry handling.
	if strings.TrimSpace(runID) != "" {
		req = append(req, pbFieldStr(25, runID)...)
	}
	return pbFieldLD(1, req)
}

func cursorBuildRunFrames(prompt, modelID, _ string, params []cursorModelParam, tools []cursorClientTool) [][]byte {
	convID := uuid.NewString()
	msgID := uuid.NewString()
	runID := uuid.NewString()
	return [][]byte{cursorEncodeConnectFrame(0, cursorEncodeRunRequest(prompt, modelID, convID, msgID, runID, params, tools))}
}

type cursorBidiExec struct {
	ID     uint64
	ExecID string
	Name   string
	CallID string
}

func cursorExtractAnswerText(payload []byte) string {
	// AgentServerMessage.interaction_update(1).text_delta(1).text(1)
	top := pbIter(payload)
	iu := pbFirstLD(top, 1)
	if iu == nil {
		return ""
	}
	td := pbFirstLD(pbIter(iu), 1)
	if td == nil {
		return ""
	}
	return pbFirstStr(pbIter(td), 1)
}

func cursorExtractTurnEnded(payload []byte) bool {
	top := pbIter(payload)
	iu := pbFirstLD(top, 1)
	if iu == nil {
		return false
	}
	_, ok := pbFirst(pbIter(iu), 14)
	return ok
}

func cursorExtractConnectError(payload []byte) error {
	msg := strings.TrimSpace(string(payload))
	if msg == "" || msg == "{}" {
		return nil
	}
	errText := gjson.Get(msg, "error.message").String()
	if errText == "" {
		errText = gjson.Get(msg, "error").String()
	}
	if errText == "" {
		errText = msg
	}
	code := int(gjson.Get(msg, "error.code").Int())
	if code == 0 {
		code = 502
	}
	return statusErr{code: code, msg: "cursor agent: " + errText}
}

func cursorExtractMcpToolCall(payload []byte) (cursorBidiExec, string, bool) {
	// AgentServerMessage.exec_server_message(2).mcp_args(11)
	top := pbIter(payload)
	exec := pbFirstLD(top, 2)
	if exec == nil {
		return cursorBidiExec{}, "", false
	}
	ef := pbIter(exec)
	mcp := pbFirstLD(ef, 11)
	if mcp == nil {
		return cursorBidiExec{}, "", false
	}
	mf := pbIter(mcp)
	name := pbFirstStr(mf, 5)
	if name == "" {
		name = pbFirstStr(mf, 1)
	}
	if name == "" {
		return cursorBidiExec{}, "", false
	}
	argsObj := map[string]json.RawMessage{}
	for _, entry := range mf {
		if entry.Num != 2 || entry.Wire != 2 {
			continue
		}
		eflds := pbIter(entry.Data)
		key := pbFirstStr(eflds, 1)
		val := pbFirstLD(eflds, 2)
		if key != "" {
			argsObj[key] = cursorDecodeJSONValue(val, 0)
		}
	}
	args, _ := json.Marshal(argsObj)
	if len(args) == 0 {
		args = []byte("{}")
	}
	idField, _ := pbFirst(ef, 1)
	callID := pbFirstStr(mf, 3)
	if callID == "" {
		callID = "call_" + uuid.NewString()
	}
	return cursorBidiExec{
		ID:     pbVarintValue(idField.Data),
		ExecID: pbFirstStr(ef, 15),
		Name:   name,
		CallID: callID,
	}, string(args), true
}

func cursorEncodeMcpToolResult(exec cursorBidiExec, content string) []byte {
	text := pbFieldLD(1, pbFieldStr(1, content))
	success := pbFieldLD(1, text)
	result := pbFieldLD(1, success)
	msg := pbFieldVarint(1, exec.ID)
	if exec.ExecID != "" {
		msg = append(msg, pbFieldStr(15, exec.ExecID)...)
	}
	msg = append(msg, pbFieldLD(11, result)...)
	return pbFieldLD(2, msg)
}

func cursorEncodeMcpToolError(exec cursorBidiExec, errText string) []byte {
	result := pbFieldLD(2, pbFieldStr(1, errText))
	msg := pbFieldVarint(1, exec.ID)
	if exec.ExecID != "" {
		msg = append(msg, pbFieldStr(15, exec.ExecID)...)
	}
	msg = append(msg, pbFieldLD(11, result)...)
	return pbFieldLD(2, msg)
}

func cursorConnectEndFrame() []byte {
	return cursorEncodeConnectFrame(cursorConnectFlagEnd, []byte("{}"))
}

func cursorDecodeStreamFrame(r io.Reader) (flags byte, payload []byte, err error) {
	frame, err := cursorDecodeConnectFrame(r)
	if err != nil {
		return 0, nil, err
	}
	payload, err = cursorGunzipIfNeeded(frame.Flags, frame.Payload)
	if err != nil {
		return frame.Flags, nil, fmt.Errorf("cursor connect gzip: %w", err)
	}
	return frame.Flags, payload, nil
}
