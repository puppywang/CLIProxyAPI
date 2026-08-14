package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Cursor's AgentService does not proxy local execution through MCP. The
// server sends one of these ExecServerMessage oneofs and the client answers
// with the matching ExecClientMessage oneof on the same bidi stream.
type cursorLocalExecKind uint8

const (
	cursorLocalExecShell cursorLocalExecKind = iota + 1
	cursorLocalExecWrite
	cursorLocalExecDelete
	cursorLocalExecGrep
	cursorLocalExecRead
	cursorLocalExecLs
	cursorLocalExecDiagnostics
)

type cursorLocalExecRequest struct {
	cursorBidiExec
	Kind        cursorLocalExecKind
	ResultField uint64

	Command         string
	WorkingDir      string
	TimeoutMS       int
	HardTimeoutMS   int
	IsBackground    bool
	Path            string
	ReturnContent   bool
	FileText        string
	FileBytes       []byte
	FileBytesSet    bool
	ReadOffset      int
	ReadLimit       uint64
	ReadLimitSet    bool
	Pattern         string
	Glob            string
	OutputMode      string
	ContextBefore   int
	ContextAfter    int
	CaseInsensitive bool
	HeadLimit       int
	Multiline       bool
	SortMode        string
	SortAscending   bool
	GrepOffset      int
	GrepOffsetSet   bool
	Ignore          []string
}

func cursorWorkspaceHint(headers http.Header) string {
	if headers == nil {
		return ""
	}
	for _, name := range []string{
		"X-Cursor-Workspace",
		"X-Workspace-Root",
		"X-Cursor-Cwd",
		"X-Cwd",
	} {
		if value := strings.TrimSpace(headers.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func cursorDefaultWorkspace(hint string) string {
	// A deployment-level workspace is authoritative. Request headers are only
	// a compatibility fallback for local/dev use; otherwise a caller could
	// select an arbitrary host directory before the lexical boundary is applied.
	root := strings.TrimSpace(os.Getenv("CURSOR_AGENT_WORKSPACE"))
	if root == "" {
		root = strings.TrimSpace(hint)
	}
	if root == "" {
		root, _ = os.Getwd()
	}
	if absolute, err := filepath.Abs(root); err == nil {
		root = absolute
	}
	return filepath.Clean(root)
}

func cursorPathWithinRoot(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

// cursorResolveWorkspacePath applies both a lexical workspace boundary and a
// symlink boundary. The latter matters for read/write operations: a path which
// is lexically inside the workspace must not escape through an existing
// symlink, including a broken final symlink that would otherwise be followed
// by a write.
func cursorResolveWorkspacePath(root, raw string) (string, error) {
	root = cursorDefaultWorkspace(root)
	if raw == "" {
		raw = root
	}
	candidate := raw
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	if !cursorPathWithinRoot(root, candidate) {
		return "", fmt.Errorf("path %q is outside workspace %q", raw, root)
	}

	rootReal := root
	if resolved, resolveErr := filepath.EvalSymlinks(root); resolveErr == nil {
		rootReal = filepath.Clean(resolved)
	}
	if err := cursorCheckSymlinkComponents(root, rootReal, candidate, raw); err != nil {
		return "", err
	}
	return candidate, nil
}

func cursorCheckSymlinkComponents(root, rootReal, candidate, raw string) error {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	current := root
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, lstatErr := os.Lstat(current)
		if lstatErr != nil {
			if os.IsNotExist(lstatErr) {
				// Once a component is absent, all later components are absent too;
				// the write path will report a normal parent-not-found error.
				break
			}
			return lstatErr
		}
		if info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr != nil {
			return fmt.Errorf("path %q contains an unresolved symlink: %w", raw, resolveErr)
		}
		if !cursorPathWithinRoot(rootReal, filepath.Clean(resolved)) {
			return fmt.Errorf("path %q escapes workspace through symlink", raw)
		}
	}
	return nil
}

func cursorFirstVarint(fields []pbField, number uint64) (uint64, bool) {
	field, ok := pbFirst(fields, number)
	if !ok || field.Wire != 0 {
		return 0, false
	}
	return pbVarintValue(field.Data), true
}

func cursorFirstInt32(fields []pbField, number uint64) (int32, bool) {
	value, ok := cursorFirstVarint(fields, number)
	if !ok {
		return 0, false
	}
	return int32(uint32(value)), true
}

func cursorAllStrings(fields []pbField, number uint64) []string {
	var values []string
	for _, field := range fields {
		if field.Num == number && field.Wire == 2 {
			values = append(values, string(field.Data))
		}
	}
	return values
}

func cursorExtractLocalExec(payload []byte) (cursorLocalExecRequest, bool) {
	top := pbIter(payload)
	message, ok := pbFirstMessage(top, 2) // AgentServerMessage.exec_server_message
	if !ok {
		return cursorLocalExecRequest{}, false
	}
	fields := pbIter(message)
	var exec cursorLocalExecRequest
	if id, ok := cursorFirstVarint(fields, 1); ok {
		exec.ID = id
	}
	exec.ExecID = pbFirstStr(fields, 15)

	if args, ok := pbFirstMessage(fields, 2); ok {
		exec.Kind = cursorLocalExecShell
		parseCursorShellArgs(&exec, pbIter(args))
		return exec, true
	}
	if args, ok := pbFirstMessage(fields, 3); ok {
		exec.Kind = cursorLocalExecWrite
		parseCursorWriteArgs(&exec, pbIter(args))
		return exec, true
	}
	if args, ok := pbFirstMessage(fields, 4); ok {
		exec.Kind = cursorLocalExecDelete
		exec.Path = pbFirstStr(pbIter(args), 1)
		return exec, true
	}
	if args, ok := pbFirstMessage(fields, 5); ok {
		exec.Kind = cursorLocalExecGrep
		parseCursorGrepArgs(&exec, pbIter(args))
		return exec, true
	}
	if args, ok := pbFirstMessage(fields, 7); ok {
		exec.Kind = cursorLocalExecRead
		parseCursorReadArgs(&exec, pbIter(args))
		return exec, true
	}
	if args, ok := pbFirstMessage(fields, 29); ok {
		exec.Kind = cursorLocalExecRead
		exec.ResultField = 29
		parseCursorReadArgs(&exec, pbIter(args))
		return exec, true
	}
	if args, ok := pbFirstMessage(fields, 8); ok {
		exec.Kind = cursorLocalExecLs
		parseCursorLsArgs(&exec, pbIter(args))
		return exec, true
	}
	if args, ok := pbFirstMessage(fields, 9); ok {
		exec.Kind = cursorLocalExecDiagnostics
		exec.Path = pbFirstStr(pbIter(args), 1)
		return exec, true
	}
	return cursorLocalExecRequest{}, false
}

func parseCursorShellArgs(exec *cursorLocalExecRequest, fields []pbField) {
	exec.Command = pbFirstStr(fields, 1)
	exec.WorkingDir = pbFirstStr(fields, 2)
	if timeout, ok := cursorFirstVarint(fields, 3); ok {
		exec.TimeoutMS = int(timeout)
	}
	if timeout, ok := cursorFirstVarint(fields, 14); ok {
		exec.HardTimeoutMS = int(timeout)
	}
	if background, ok := cursorFirstVarint(fields, 11); ok {
		exec.IsBackground = background != 0
	}
}

func parseCursorWriteArgs(exec *cursorLocalExecRequest, fields []pbField) {
	exec.Path = pbFirstStr(fields, 1)
	exec.FileText = pbFirstStr(fields, 2)
	if field, ok := pbFirst(fields, 4); ok && field.Wire == 0 {
		exec.ReturnContent = pbVarintValue(field.Data) != 0
	}
	if field, ok := pbFirst(fields, 5); ok && field.Wire == 2 {
		exec.FileBytes = append([]byte(nil), field.Data...)
		exec.FileBytesSet = true
	}
}

func parseCursorReadArgs(exec *cursorLocalExecRequest, fields []pbField) {
	exec.Path = pbFirstStr(fields, 1)
	if offset, ok := cursorFirstInt32(fields, 4); ok {
		exec.ReadOffset = int(offset)
	}
	if limit, ok := cursorFirstVarint(fields, 5); ok {
		exec.ReadLimit = limit
		exec.ReadLimitSet = true
	}
}

func parseCursorGrepArgs(exec *cursorLocalExecRequest, fields []pbField) {
	exec.Pattern = pbFirstStr(fields, 1)
	exec.Path = pbFirstStr(fields, 2)
	exec.Glob = pbFirstStr(fields, 3)
	exec.OutputMode = pbFirstStr(fields, 4)
	// agent.v1.GrepArgs field 14 is tool_call_id. Unlike the newer
	// aiserver.v1.RipgrepArgs shape, this message has no ignore-globs field.
	hasBefore, hasAfter := false, false
	if value, ok := cursorFirstVarint(fields, 5); ok {
		exec.ContextBefore = int(value)
		hasBefore = true
	}
	if value, ok := cursorFirstVarint(fields, 6); ok {
		exec.ContextAfter = int(value)
		hasAfter = true
	}
	if value, ok := cursorFirstVarint(fields, 7); ok {
		if !hasBefore {
			exec.ContextBefore = int(value)
		}
		if !hasAfter {
			exec.ContextAfter = int(value)
		}
	}
	if value, ok := cursorFirstVarint(fields, 8); ok {
		exec.CaseInsensitive = value != 0
	}
	if value, ok := cursorFirstVarint(fields, 10); ok {
		exec.HeadLimit = int(value)
	}
	if value, ok := cursorFirstVarint(fields, 11); ok {
		exec.Multiline = value != 0
	}
	exec.SortMode = pbFirstStr(fields, 12)
	if value, ok := cursorFirstVarint(fields, 13); ok {
		exec.SortAscending = value != 0
	}
	if value, ok := cursorFirstVarint(fields, 16); ok {
		exec.GrepOffset = int(value)
		exec.GrepOffsetSet = true
	}
}

func parseCursorLsArgs(exec *cursorLocalExecRequest, fields []pbField) {
	exec.Path = pbFirstStr(fields, 1)
	exec.Ignore = cursorAllStrings(fields, 2)
	if timeout, ok := cursorFirstVarint(fields, 5); ok {
		exec.TimeoutMS = int(timeout)
	}
}

func cursorExecClientMessage(exec cursorLocalExecRequest, resultField uint64, result []byte, elapsed time.Duration) []byte {
	message := pbFieldVarint(1, exec.ID)
	if exec.ExecID != "" {
		message = append(message, pbFieldStr(15, exec.ExecID)...)
	}
	if elapsed >= 0 {
		message = append(message, pbFieldVarint(39, uint64(elapsed/time.Millisecond))...)
	}
	message = append(message, pbFieldLD(resultField, result)...)
	return pbFieldLD(2, message) // AgentClientMessage.exec_client_message
}

func cursorEncodeLocalExecResult(ctx context.Context, root string, exec cursorLocalExecRequest) []byte {
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now()
	var resultField uint64
	var result []byte
	switch exec.Kind {
	case cursorLocalExecShell:
		resultField = 2
		result = cursorExecuteShell(ctx, root, exec)
	case cursorLocalExecWrite:
		resultField = 3
		result = cursorExecuteWrite(root, exec)
	case cursorLocalExecDelete:
		resultField = 4
		result = cursorExecuteDelete(root, exec)
	case cursorLocalExecGrep:
		resultField = 5
		result = cursorExecuteGrep(root, exec)
	case cursorLocalExecRead:
		resultField = exec.ResultField
		if resultField == 0 {
			resultField = 7
		}
		result = cursorExecuteRead(root, exec)
	case cursorLocalExecLs:
		resultField = 8
		result = cursorExecuteLs(root, exec)
	case cursorLocalExecDiagnostics:
		resultField = 9
		result = cursorExecuteDiagnostics(root, exec)
	default:
		return nil
	}
	return cursorExecClientMessage(exec, resultField, result, time.Since(started))
}

func cursorExecuteShell(ctx context.Context, root string, execRequest cursorLocalExecRequest) []byte {
	if execRequest.IsBackground {
		return pbFieldLD(4, cursorShellRejected(execRequest.Command, execRequest.WorkingDir, "background shell execution is not supported"))
	}
	workingDir := execRequest.WorkingDir
	if workingDir == "" {
		workingDir = root
	}
	workingDir, err := cursorResolveWorkspacePath(root, workingDir)
	if err != nil {
		return pbFieldLD(4, cursorShellRejected(execRequest.Command, execRequest.WorkingDir, err.Error()))
	}

	timeoutMS := execRequest.TimeoutMS
	if timeoutMS <= 0 && execRequest.HardTimeoutMS > 0 {
		timeoutMS = execRequest.HardTimeoutMS
	}
	if timeoutMS <= 0 {
		timeoutMS = 120000
	}
	if timeoutMS > 10*60*1000 {
		timeoutMS = 10 * 60 * 1000
	}
	commandCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMS)*time.Millisecond)
	defer cancel()

	var command *exec.Cmd
	if runtime.GOOS == "windows" {
		command = exec.CommandContext(commandCtx, "cmd.exe", "/d", "/s", "/c", execRequest.Command)
	} else {
		command = exec.CommandContext(commandCtx, "/bin/sh", "-lc", execRequest.Command)
	}
	command.Dir = workingDir
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	started := time.Now()
	err = command.Run()
	elapsedMS := int(time.Since(started) / time.Millisecond)
	out := cursorTrimCommandOutput(stdout.String())
	errOut := cursorTrimCommandOutput(stderr.String())

	if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
		timeout := pbFieldStr(1, execRequest.Command)
		timeout = append(timeout, pbFieldStr(2, workingDir)...)
		timeout = append(timeout, pbFieldVarint(3, uint64(timeoutMS))...)
		return pbFieldLD(3, timeout)
	}
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return pbFieldLD(5, cursorShellSpawnError(execRequest.Command, workingDir, err.Error()))
		}
		exitCode := command.ProcessState.ExitCode()
		failure := cursorShellCommon(execRequest.Command, workingDir, exitCode, out, errOut, elapsedMS)
		failure = append(failure, pbFieldStr(9, joinCommandOutput(out, errOut))...)
		failure = append(failure, pbFieldVarint(11, 0)...)
		failure = append(failure, pbFieldVarint(12, uint64(elapsedMS))...)
		return pbFieldLD(2, failure)
	}

	success := cursorShellCommon(execRequest.Command, workingDir, 0, out, errOut, elapsedMS)
	success = append(success, pbFieldStr(10, joinCommandOutput(out, errOut))...)
	success = append(success, pbFieldVarint(13, uint64(elapsedMS))...)
	return pbFieldLD(1, success)
}

func cursorShellCommon(command, workingDir string, exitCode int, stdout, stderr string, elapsedMS int) []byte {
	result := pbFieldStr(1, command)
	result = append(result, pbFieldStr(2, workingDir)...)
	result = append(result, pbFieldVarint(3, uint64(exitCode))...)
	result = append(result, pbFieldStr(5, stdout)...)
	result = append(result, pbFieldStr(6, stderr)...)
	result = append(result, pbFieldVarint(7, uint64(elapsedMS))...)
	return result
}

func cursorShellRejected(command, workingDir, reason string) []byte {
	result := pbFieldStr(1, command)
	result = append(result, pbFieldStr(2, workingDir)...)
	result = append(result, pbFieldStr(3, reason)...)
	result = append(result, pbFieldVarint(4, 1)...)
	return result
}

func cursorShellSpawnError(command, workingDir, message string) []byte {
	result := pbFieldStr(1, command)
	result = append(result, pbFieldStr(2, workingDir)...)
	result = append(result, pbFieldStr(3, message)...)
	return result
}

func joinCommandOutput(stdout, stderr string) string {
	if stdout == "" {
		return stderr
	}
	if stderr == "" {
		return stdout
	}
	return stdout + "\n" + stderr
}

func cursorTrimCommandOutput(value string) string {
	const maxOutput = 1024 * 1024
	if len(value) <= maxOutput {
		return value
	}
	const half = maxOutput / 2
	return value[:half] + "\n[output truncated]\n" + value[len(value)-half:]
}

func cursorExecuteRead(root string, execRequest cursorLocalExecRequest) []byte {
	path, err := cursorResolveWorkspacePath(root, execRequest.Path)
	if err != nil {
		return pbFieldLD(3, cursorPathReason(execRequest.Path, err.Error()))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return pbFieldLD(4, pbFieldStr(1, path))
		}
		if os.IsPermission(err) {
			return pbFieldLD(5, pbFieldStr(1, path))
		}
		return pbFieldLD(2, cursorPathError(path, err.Error()))
	}
	info, err := os.Stat(path)
	if err != nil {
		return pbFieldLD(2, cursorPathError(path, err.Error()))
	}
	if !info.Mode().IsRegular() {
		return pbFieldLD(6, cursorPathReason(path, "not a regular file"))
	}

	// ReadArgs offset/limit are line-oriented in the Cursor agent tool. Keep
	// line endings in the selected range so the model receives the same text it
	// would have seen from the CLI's file reader.
	lines := splitReadLines(data)
	start := execRequest.ReadOffset
	if start < 0 {
		start = 0
	}
	if start > len(lines) {
		start = len(lines)
	}
	end := len(lines)
	if execRequest.ReadLimitSet && execRequest.ReadLimit < uint64(end-start) {
		end = start + int(execRequest.ReadLimit)
	}
	selected := joinReadLines(lines[start:end])
	content := string(selected)
	result := pbFieldStr(1, path)
	result = append(result, pbFieldStr(2, content)...)
	result = append(result, pbFieldVarint(3, uint64(len(lines)))...)
	result = append(result, pbFieldVarint(4, uint64(info.Size()))...)
	if end < len(lines) {
		result = append(result, pbFieldVarint(6, 1)...)
	}
	if start != 0 || end != len(lines) || execRequest.ReadLimitSet {
		result = append(result, pbFieldVarint(8, 1)...)
	}
	return pbFieldLD(1, result)
}

func splitReadLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	lines := strings.SplitAfter(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func joinReadLines(lines []string) []byte {
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, ""))
}

func cursorExecuteWrite(root string, execRequest cursorLocalExecRequest) []byte {
	path, err := cursorResolveWorkspacePath(root, execRequest.Path)
	if err != nil {
		return pbFieldLD(6, cursorPathReason(execRequest.Path, err.Error()))
	}
	data := []byte(execRequest.FileText)
	if execRequest.FileBytesSet {
		data = execRequest.FileBytes
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		if os.IsPermission(err) {
			permission := pbFieldStr(1, path)
			permission = append(permission, pbFieldStr(2, filepath.Dir(path))...)
			permission = append(permission, pbFieldStr(3, "write")...)
			permission = append(permission, pbFieldStr(4, err.Error())...)
			return pbFieldLD(3, permission)
		}
		if errors.Is(err, syscall.ENOSPC) {
			return pbFieldLD(4, pbFieldStr(1, path))
		}
		return pbFieldLD(5, cursorPathError(path, err.Error()))
	}
	success := pbFieldStr(1, path)
	success = append(success, pbFieldVarint(2, uint64(countTextLines(string(data))))...)
	success = append(success, pbFieldVarint(3, uint64(len(data)))...)
	if execRequest.ReturnContent {
		success = append(success, pbFieldStr(4, string(data))...)
	}
	return pbFieldLD(1, success)
}

func cursorExecuteDelete(root string, execRequest cursorLocalExecRequest) []byte {
	path, err := cursorResolveWorkspacePath(root, execRequest.Path)
	if err != nil {
		return pbFieldLD(6, cursorPathReason(execRequest.Path, err.Error()))
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return pbFieldLD(2, pbFieldStr(1, path))
		}
		if os.IsPermission(err) {
			permission := pbFieldStr(1, path)
			permission = append(permission, pbFieldStr(2, err.Error())...)
			return pbFieldLD(4, permission)
		}
		return pbFieldLD(7, cursorPathError(path, err.Error()))
	}
	if info.IsDir() {
		notFile := pbFieldStr(1, path)
		notFile = append(notFile, pbFieldStr(2, "directory")...)
		return pbFieldLD(3, notFile)
	}
	previous, _ := os.ReadFile(path)
	if err := os.Remove(path); err != nil {
		if os.IsPermission(err) {
			permission := pbFieldStr(1, path)
			permission = append(permission, pbFieldStr(2, err.Error())...)
			return pbFieldLD(4, permission)
		}
		return pbFieldLD(7, cursorPathError(path, err.Error()))
	}
	success := pbFieldStr(1, path)
	// DeleteSuccess.deleted_file is the deleted path; prev_content carries the
	// optional contents captured before unlinking. This matches the official
	// local delete executor construction.
	success = append(success, pbFieldStr(2, path)...)
	success = append(success, pbFieldVarint(3, uint64(info.Size()))...)
	success = append(success, pbFieldStr(4, string(previous))...)
	return pbFieldLD(1, success)
}

func cursorExecuteLs(root string, execRequest cursorLocalExecRequest) []byte {
	path, err := cursorResolveWorkspacePath(root, execRequest.Path)
	if err != nil {
		return pbFieldLD(3, cursorPathReason(execRequest.Path, err.Error()))
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return pbFieldLD(2, cursorPathError(path, err.Error()))
	}
	ignore := func(name string) bool {
		for _, pattern := range execRequest.Ignore {
			matched, _ := pathpkg.Match(pattern, name)
			if matched || name == pattern {
				return true
			}
		}
		return false
	}
	tree := pbFieldStr(1, path)
	for _, entry := range entries {
		if ignore(entry.Name()) {
			continue
		}
		if entry.IsDir() {
			dir := pbFieldStr(1, filepath.Join(path, entry.Name()))
			tree = append(tree, pbFieldLD(2, dir)...)
			continue
		}
		file := pbFieldStr(1, entry.Name())
		tree = append(tree, pbFieldLD(3, file)...)
	}
	success := pbFieldLD(1, tree)
	return pbFieldLD(1, success)
}

type cursorGrepFile struct {
	path    string
	matches []cursorGrepMatch
}

type cursorGrepMatch struct {
	line             int
	content          string
	isContext        bool
	contentTruncated bool
}

func cursorExecuteGrep(root string, execRequest cursorLocalExecRequest) []byte {
	searchPath, err := cursorResolveWorkspacePath(root, execRequest.Path)
	if err != nil {
		return pbFieldLD(2, pbFieldStr(1, err.Error()))
	}
	pattern := execRequest.Pattern
	if execRequest.CaseInsensitive {
		pattern = "(?i)" + pattern
	}
	if execRequest.Multiline {
		pattern = "(?s)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return pbFieldLD(2, pbFieldStr(1, err.Error()))
	}
	var files []cursorGrepFile
	visit := func(path string, data []byte) {
		if bytes.IndexByte(data, 0) >= 0 {
			return
		}
		text := string(data)
		lines := strings.Split(text, "\n")
		var matchedLines []int
		for index, line := range lines {
			if re.MatchString(line) {
				matchedLines = append(matchedLines, index)
			}
		}
		if len(matchedLines) == 0 && execRequest.Multiline && re.MatchString(text) {
			matchedLines = append(matchedLines, 0)
		}
		if len(matchedLines) == 0 {
			return
		}
		lineSet := make(map[int]bool, len(matchedLines))
		for _, index := range matchedLines {
			lineSet[index] = true
		}
		before, after := execRequest.ContextBefore, execRequest.ContextAfter
		if context := execRequest.ContextBefore; context > 0 && execRequest.ContextAfter == 0 {
			after = context
		}
		if context := execRequest.ContextAfter; context > 0 && execRequest.ContextBefore == 0 {
			before = context
		}
		included := make(map[int]bool)
		for _, index := range matchedLines {
			start := index - before
			if start < 0 {
				start = 0
			}
			end := index + after
			if end >= len(lines) {
				end = len(lines) - 1
			}
			for lineIndex := start; lineIndex <= end; lineIndex++ {
				included[lineIndex] = true
			}
		}
		var matches []cursorGrepMatch
		for index := 0; index < len(lines); index++ {
			if included[index] {
				matches = append(matches, cursorGrepMatch{
					line:      index + 1,
					content:   lines[index],
					isContext: !lineSet[index],
				})
			}
		}
		if len(matches) == 0 {
			return
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			relative = path
		}
		files = append(files, cursorGrepFile{path: filepath.ToSlash(relative), matches: matches})
	}
	info, err := os.Stat(searchPath)
	if err != nil {
		return pbFieldLD(2, pbFieldStr(1, err.Error()))
	}
	if !info.IsDir() {
		if data, readErr := os.ReadFile(searchPath); readErr == nil {
			visit(searchPath, data)
		}
	} else {
		walkErr := filepath.WalkDir(searchPath, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if execRequest.Glob != "" && !cursorGlobMatches(root, path, execRequest.Glob) {
				return nil
			}
			resolvedPath, resolveErr := cursorResolveWorkspacePath(root, path)
			if resolveErr != nil {
				return nil
			}
			data, readErr := os.ReadFile(resolvedPath)
			if readErr == nil {
				visit(resolvedPath, data)
			}
			return nil
		})
		if walkErr != nil {
			return pbFieldLD(2, pbFieldStr(1, walkErr.Error()))
		}
	}
	if execRequest.SortMode == "" || execRequest.SortMode == "modified" {
		sort.Slice(files, func(i, j int) bool {
			left, leftErr := os.Stat(filepath.Join(root, filepath.FromSlash(files[i].path)))
			right, rightErr := os.Stat(filepath.Join(root, filepath.FromSlash(files[j].path)))
			if leftErr != nil || rightErr != nil {
				return files[i].path < files[j].path
			}
			if execRequest.SortAscending {
				return left.ModTime().Before(right.ModTime())
			}
			return left.ModTime().After(right.ModTime())
		})
	}
	for _, ignore := range execRequest.Ignore {
		for i := len(files) - 1; i >= 0; i-- {
			if matched, _ := pathpkg.Match(filepath.ToSlash(ignore), files[i].path); matched || files[i].path == ignore {
				files = append(files[:i], files[i+1:]...)
			}
		}
	}
	if execRequest.SortMode == "none" {
		sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	} else if execRequest.SortMode != "" && execRequest.SortMode != "modified" {
		sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	}
	totalFiles := len(files)
	totalMatches := 0
	for _, file := range files {
		totalMatches += cursorGrepMatchedCount(file)
	}
	if execRequest.GrepOffsetSet && execRequest.GrepOffset > 0 {
		if execRequest.GrepOffset >= len(files) {
			files = nil
		} else {
			files = files[execRequest.GrepOffset:]
		}
	}
	clientTruncated := false
	if execRequest.HeadLimit > 0 && len(files) > execRequest.HeadLimit {
		files = files[:execRequest.HeadLimit]
		clientTruncated = true
	}
	mode := strings.ToLower(execRequest.OutputMode)
	if mode == "" {
		mode = "content"
	}
	success := pbFieldStr(1, execRequest.Pattern)
	success = append(success, pbFieldStr(2, searchPath)...)
	success = append(success, pbFieldStr(3, mode)...)
	union := cursorEncodeGrepUnion(files, mode, totalFiles, totalMatches, clientTruncated, execRequest.GrepOffsetSet, execRequest.HeadLimit > 0)
	entry := pbFieldStr(1, cursorDefaultWorkspace(root))
	entry = append(entry, pbFieldLD(2, union)...)
	success = append(success, pbFieldLD(4, entry)...)
	return pbFieldLD(1, success)
}

func cursorGlobMatches(root, candidate, glob string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	relative = filepath.ToSlash(relative)
	glob = filepath.ToSlash(glob)
	if matched, _ := pathpkg.Match(glob, relative); matched {
		return true
	}
	if matched, _ := pathpkg.Match(glob, pathpkg.Base(relative)); matched {
		return true
	}
	if strings.HasPrefix(glob, "**/") {
		matched, _ := pathpkg.Match(strings.TrimPrefix(glob, "**/"), relative)
		return matched
	}
	return false
}

func cursorEncodeGrepUnion(files []cursorGrepFile, mode string, totalFiles, totalMatches int, clientTruncated, offsetApplied, headLimitApplied bool) []byte {
	switch mode {
	case "files", "file":
		result := make([]byte, 0)
		for _, file := range files {
			result = append(result, pbFieldStr(1, file.path)...)
		}
		result = append(result, pbFieldVarint(2, uint64(totalFiles))...)
		if clientTruncated {
			result = append(result, pbFieldVarint(3, 1)...)
		}
		if headLimitApplied {
			result = append(result, pbFieldVarint(5, 1)...)
		}
		if offsetApplied {
			result = append(result, pbFieldVarint(6, 1)...)
		}
		return pbFieldLD(2, result)
	case "count":
		result := make([]byte, 0)
		for _, file := range files {
			count := pbFieldStr(1, file.path)
			count = append(count, pbFieldVarint(2, uint64(cursorGrepMatchedCount(file)))...)
			result = append(result, pbFieldLD(1, count)...)
		}
		result = append(result, pbFieldVarint(2, uint64(totalFiles))...)
		result = append(result, pbFieldVarint(3, uint64(totalMatches))...)
		if clientTruncated {
			result = append(result, pbFieldVarint(4, 1)...)
		}
		if headLimitApplied {
			result = append(result, pbFieldVarint(6, 1)...)
		}
		if offsetApplied {
			result = append(result, pbFieldVarint(7, 1)...)
		}
		return pbFieldLD(1, result)
	default:
		content := cursorEncodeGrepFileMatches(files, clientTruncated, offsetApplied, headLimitApplied)
		content = append(content, pbFieldVarint(2, uint64(cursorGrepTotalLines(files)))...)
		content = append(content, pbFieldVarint(3, uint64(totalMatches))...)
		return pbFieldLD(3, content)
	}
}

func cursorGrepMatchedCount(file cursorGrepFile) int {
	count := 0
	for _, match := range file.matches {
		if !match.isContext {
			count++
		}
	}
	return count
}
func cursorGrepTotalLines(files []cursorGrepFile) int {
	total := 0
	for _, file := range files {
		total += len(file.matches)
	}
	return total
}

func cursorEncodeGrepFileMatches(files []cursorGrepFile, clientTruncated, offsetApplied, headLimitApplied bool) []byte {
	content := make([]byte, 0)
	for _, file := range files {
		fileMatches := pbFieldStr(1, file.path)
		for _, match := range file.matches {
			item := pbFieldVarint(1, uint64(match.line))
			item = append(item, pbFieldStr(2, match.content)...)
			if match.contentTruncated {
				item = append(item, pbFieldVarint(3, 1)...)
			}
			if match.isContext {
				item = append(item, pbFieldVarint(4, 1)...)
			}
			fileMatches = append(fileMatches, pbFieldLD(2, item)...)
		}
		content = append(content, pbFieldLD(1, fileMatches)...)
	}
	if clientTruncated {
		content = append(content, pbFieldVarint(4, 1)...)
	}
	if offsetApplied {
		content = append(content, pbFieldVarint(7, 1)...)
	}
	if headLimitApplied {
		content = append(content, pbFieldVarint(6, 1)...)
	}
	return content
}

func cursorExecuteDiagnostics(root string, execRequest cursorLocalExecRequest) []byte {
	path, err := cursorResolveWorkspacePath(root, execRequest.Path)
	if err != nil {
		return pbFieldLD(3, cursorPathReason(execRequest.Path, err.Error()))
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return pbFieldLD(4, pbFieldStr(1, path))
		}
		if os.IsPermission(err) {
			return pbFieldLD(5, pbFieldStr(1, path))
		}
		return pbFieldLD(2, cursorPathError(path, err.Error()))
	}
	if !info.Mode().IsRegular() {
		return pbFieldLD(2, cursorPathError(path, "not a regular file"))
	}
	return cursorEncodeDiagnosticsSuccess(path)
}

func cursorEncodeDiagnosticsSuccess(path string) []byte {
	success := pbFieldStr(1, path)
	success = append(success, pbFieldVarint(3, 0)...)
	return pbFieldLD(1, success)
}

func cursorPathError(path, message string) []byte {
	result := pbFieldStr(1, path)
	result = append(result, pbFieldStr(2, message)...)
	return result
}

func cursorPathReason(path, reason string) []byte {
	result := pbFieldStr(1, path)
	result = append(result, pbFieldStr(2, reason)...)
	return result
}

func countTextLines(value string) int {
	if value == "" {
		return 0
	}
	count := strings.Count(value, "\n")
	if !strings.HasSuffix(value, "\n") {
		count++
	}
	return count
}
