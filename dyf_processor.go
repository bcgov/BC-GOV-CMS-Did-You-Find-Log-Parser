package main

import (
	"bufio"
	"container/heap"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/zstd"
)

const (
	ConfigFile         = "config.ini"
	DefaultChunkSize   = 100_000
	TimestampLayout    = "2006-01-02 15:04:05"
	LogFilenamePattern = `^\d{4}-\d{2}\.log$`
)

// ProcessImmediatelyAfterSetup controls what happens when config.ini is created
// for the first time.
//
//	false — pause after setup and exit; user reviews config.ini then runs again
//	true  — proceed directly to processing after setup with no pause
const ProcessImmediatelyAfterSetup = true

// ==============================
// Models
// ==============================

type Settings struct {
	LogDir         string
	OutputDir      string
	ProcessingMode string // "append" | "overwrite"
	ChunkSize      int
	LogLevel       string
	ErrorFile      string

	WhiteList   [][]string
	BlackList   [][]string
	SearchScope string // "url" | "full_line"
	SearchMode  string // "substring" | "word" | "regex"

	OutputFileName     string
	OutputFormat       string
	SortOutput         bool
	IncludeFileLineRef bool

	MergeMatchedReasonLines  bool
	KeepUnmatchedReasonLines bool
	KeepIFSRows              bool
	ReasonLinkWindowSeconds  int
}

type Entry struct {
	ResponseType string
	Date         string
	Time         string
	URL          string
	Reason       string
	Timestamp    time.Time
	Malformed    bool
	Index        int64
	FileName     string
	LineNumber   int64
}

type ParquetRow struct {
	ResponseType string    `parquet:"response_type"`
	Date         string    `parquet:"date"`
	Time         string    `parquet:"time"`
	URL          string    `parquet:"url"`
	Reason       string    `parquet:"reason"`
	Timestamp    time.Time `parquet:"timestamp,logical=timestamp,unit=us"`
	Index        int64     `parquet:"index"`
	FileName     string    `parquet:"file_name"`
	LineNumber   int64     `parquet:"line_number"`
}

type Stats struct {
	Written    int64
	Filtered   int64
	Malformed  int64
	Duplicates int64
}

var validResponseTypes = map[string]bool{
	"Reason": true, "Yes": true, "No": true, "IFS": true,
}

var validReasons = map[string]bool{
	"Missing": true, "Unclear": true, "Other": true, "Unrelated": true,
}

// ==============================
// Main
// ==============================

func main() {
	if ensureConfig() && !ProcessImmediatelyAfterSetup {
		return
	}
	settings, err := loadConfig()
	if err != nil {
		fmt.Println("Error loading config:", err)
		return
	}
	fmt.Println("\nLoaded configuration:")
	fmt.Printf("%+v\n\n", settings)
	if err := processLogs(settings); err != nil {
		fmt.Println("Processing error:", err)
	}
}

// ==============================
// Config
// ==============================

// ensureConfig creates config.ini interactively if it does not exist.
// Returns true when a new config was written — caller should exit so the
// user can review before the first run.
func ensureConfig() bool {
	if _, err := os.Stat(ConfigFile); errors.Is(err, os.ErrNotExist) {
		fmt.Println("No config.ini found. Let's set up your configuration.")
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Log file directory (default: logs): ")
		logDirInput, _ := reader.ReadString('\n')
		logDir := strings.TrimSpace(logDirInput)
		if logDir == "" {
			logDir = "logs"
		}

		fmt.Print("Output directory (default: output): ")
		outDirInput, _ := reader.ReadString('\n')
		outDir := strings.TrimSpace(outDirInput)
		if outDir == "" {
			outDir = "output"
		}

		fmt.Print("White list terms — leave blank to include all URLs: ")
		whiteInput, _ := reader.ReadString('\n')
		white := strings.TrimSpace(whiteInput)

		content := fmt.Sprintf(`# Did-You-Find Log Processor — Configuration
# Review [Paths] and [Filters] before your first run.

[Paths]
; Where log files are located
log_file_archive = %s

; Where output files are saved
output_directory = %s

; append: only process new log files each run
; overwrite: reprocess all log files from scratch
processing_mode = append

[Filters]
; URL must match at least one group to be included (leave blank = include all URLs)
; Single term:   white_list = taxes
; AND group:     white_list = (taxes AND /gov/content/taxes)
; Multiple OR:   white_list = (taxes AND /content/taxes) OR (transportation AND cars)
white_list = %s

; URL is excluded if it matches any group (leave blank = exclude nothing)
; Example: black_list = (/test/) OR (/staging/)
black_list =

; url: match only the URL field    full_line: match the entire log line
search_scope = url

; substring (default)    word (whole words only)    regex
search_mode = substring

[Output]
output_file_name = Did-You-Find-Log
output_format = csv

; True sorts by URL then timestamp — requires all log files to be reprocessed each run
; False preserves original log order and supports incremental (append) processing
sort_output = True

; Add source file name and line number columns to output
include_file_line_ref = False

[Behavior]
; Attach a Reason row to its preceding No response within the time window below
merge_matched_reason_lines = True

; Keep Reason rows that could not be matched to a No response
; Tip: set merge_matched_reason_lines = False and keep_unmatched_reason_lines = True
;      to preserve the original one-row-per-log-entry structure
keep_unmatched_reason_lines = True

; IFS ("Internal Forms Service?") rows
keep_ifs_rows = False

; Maximum seconds between a No and its Reason to be treated as related
reason_link_window_seconds = 60

[Advanced]
; Rows held in memory before writing a temporary sort file
chunk_size = 100000

; Info or Debug
log_level = Info

; Malformed and rejected lines are written here (saved to output_directory)
error_log_file = error_log.txt
`, logDir, outDir, white)

		if err := os.WriteFile(ConfigFile, []byte(content), 0644); err != nil {
			fmt.Println("Error creating config.ini:", err)
			return true
		}
		fmt.Println("\nconfig.ini created.")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		if ProcessImmediatelyAfterSetup {
			fmt.Println("Proceeding with default settings.")
			fmt.Println("Edit config.ini to adjust settings for future runs.")
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		} else {
			fmt.Println("Setup complete — no files were processed.")
			fmt.Println()
			fmt.Println("Before your first run, review config.ini:")
			fmt.Println("  1. [Filters]  — set white_list to the URLs you care about")
			fmt.Println("  2. [Behavior] — choose how Reason rows are handled")
			fmt.Println("  3. [Paths]    — confirm log_file_archive and output_directory")
			fmt.Println()
			fmt.Println("Run this tool again when ready.")
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Println("\nPress Enter to exit.")
			fmt.Scanln()
		}
		return true
	}
	fmt.Println("Config file found:", ConfigFile)
	return false
}

func loadConfig() (Settings, error) {
	raw, err := os.ReadFile(ConfigFile)
	if err != nil {
		return Settings{}, err
	}
	lines := strings.Split(string(raw), "\n")
	get := func(key string) string {
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || trimmed[0] == ';' || trimmed[0] == '#' || trimmed[0] == '[' {
				continue
			}
			if strings.HasPrefix(trimmed, key+" =") || strings.HasPrefix(trimmed, key+"=") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
		return ""
	}

	chunk, _ := strconv.Atoi(defaultIfEmpty(get("chunk_size"), "100000"))
	linkWindow, _ := strconv.Atoi(defaultIfEmpty(get("reason_link_window_seconds"), "60"))

	searchScope := strings.ToLower(defaultIfEmpty(get("search_scope"), "url"))
	if searchScope != "url" && searchScope != "full_line" {
		searchScope = "url"
	}
	searchMode := strings.ToLower(defaultIfEmpty(get("search_mode"), "substring"))
	if searchMode != "substring" && searchMode != "word" && searchMode != "regex" {
		searchMode = "substring"
	}

	processingMode := strings.ToLower(defaultIfEmpty(get("processing_mode"), "append"))
	if processingMode != "append" && processingMode != "overwrite" {
		processingMode = "append"
	}

	return Settings{
		LogDir:                   get("log_file_archive"),
		OutputDir:                get("output_directory"),
		ProcessingMode:           processingMode,
		ChunkSize:                chunk,
		LogLevel:                 get("log_level"),
		ErrorFile:                defaultIfEmpty(get("error_log_file"), "error_log.txt"),
		WhiteList:                parseFilterExpression(get("white_list")),
		BlackList:                parseFilterExpression(get("black_list")),
		SearchScope:              searchScope,
		SearchMode:               searchMode,
		OutputFileName:           defaultIfEmpty(get("output_file_name"), "Did-You-Find-Log"),
		OutputFormat:             strings.ToLower(defaultIfEmpty(get("output_format"), "csv")),
		SortOutput:               strings.ToLower(defaultIfEmpty(get("sort_output"), "false")) == "true",
		IncludeFileLineRef:       strings.ToLower(defaultIfEmpty(get("include_file_line_ref"), "false")) == "true",
		MergeMatchedReasonLines:  strings.ToLower(get("merge_matched_reason_lines")) == "true",
		KeepUnmatchedReasonLines: strings.ToLower(defaultIfEmpty(get("keep_unmatched_reason_lines"), "true")) != "false",
		KeepIFSRows:              strings.ToLower(get("keep_ifs_rows")) == "true",
		ReasonLinkWindowSeconds:  linkWindow,
	}, nil
}

// ==============================
// Parsing
// ==============================

func parseLine(line string) Entry {
	parts := strings.Fields(line)
	e := Entry{Malformed: false}
	if len(parts) < 4 {
		e.Malformed = true
		return e
	}
	e.ResponseType = parts[0]
	if !validResponseTypes[e.ResponseType] {
		e.Malformed = true
		return e
	}
	e.Date = parts[1]
	e.Time = parts[2]

	urlNorm, ok, reason := normalizeURL(parts[3])
	if !ok {
		e.Malformed = true
		e.Reason = reason
		return e
	}
	e.URL = urlNorm

	if len(parts) > 4 {
		last := parts[len(parts)-1]
		if validReasons[last] {
			e.Reason = last
		} else if e.ResponseType == "Reason" {
			e.Reason = ""
		}
	}

	ts, err := time.Parse(TimestampLayout, e.Date+" "+e.Time)
	if err == nil {
		e.Timestamp = ts
	}
	return e
}

func normalizeURL(raw string) (string, bool, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, "EmptyOrInvalidURL"
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}

	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false, "EmptyOrInvalidURL"
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	path := u.EscapedPath()
	path = collapseSlashes(path)

	lp := strings.ToLower(path)
	if strings.Contains(path, "…") || strings.Contains(lp, "%e2%80%a6") {
		return "", false, "LikelyTruncated"
	}

	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}

	if !utf8.ValidString(path) {
		return "", false, "EmptyOrInvalidURL"
	}

	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""

	return u.String(), true, ""
}

func collapseSlashes(p string) string {
	if p == "" {
		return "/"
	}
	var b strings.Builder
	b.Grow(len(p))
	prevSlash := false
	for i, r := range p {
		if r == '/' {
			if i == 0 || !prevSlash {
				b.WriteRune(r)
			}
			prevSlash = true
		} else {
			b.WriteRune(r)
			prevSlash = false
		}
	}
	return b.String()
}

// ==============================
// Matching / Filtering
// ==============================

type termMatcher func(entry Entry, rawLine string) bool

// parseFilterExpression parses a white_list or black_list value into OR-of-AND groups.
// Syntax: (term1 AND term2) OR (term3 AND term4)
func parseFilterExpression(s string) [][]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var groups [][]string
	for _, groupStr := range strings.Split(s, " OR ") {
		groupStr = strings.TrimSpace(groupStr)
		if strings.HasPrefix(groupStr, "(") && strings.HasSuffix(groupStr, ")") {
			groupStr = groupStr[1 : len(groupStr)-1]
		}
		var terms []string
		for _, term := range strings.Split(groupStr, " AND ") {
			t := strings.TrimSpace(strings.ToLower(term))
			if t != "" {
				terms = append(terms, t)
			}
		}
		if len(terms) > 0 {
			groups = append(groups, terms)
		}
	}
	return groups
}

func buildMatcher(s Settings) termMatcher {
	white := s.WhiteList
	black := s.BlackList

	if len(white) == 0 && len(black) == 0 {
		return func(_ Entry, _ string) bool { return true }
	}

	switch s.SearchMode {
	case "regex":
		whiteRegGroups := compileRegexGroups(white)
		blackRegGroups := compileRegexGroups(black)
		return func(e Entry, raw string) bool {
			target := raw
			if s.SearchScope == "url" {
				target = e.URL
			}
			lt := strings.ToLower(target)
			for _, group := range blackRegGroups {
				if allRegexMatch(lt, group) {
					return false
				}
			}
			if len(whiteRegGroups) == 0 {
				return true
			}
			for _, group := range whiteRegGroups {
				if allRegexMatch(lt, group) {
					return true
				}
			}
			return false
		}

	case "word":
		splitter := regexp.MustCompile(`[A-Za-z0-9_]+`)
		return func(e Entry, raw string) bool {
			target := raw
			if s.SearchScope == "url" {
				target = e.URL
			}
			lt := strings.ToLower(target)
			tokens := splitter.FindAllString(lt, -1)
			set := make(map[string]struct{}, len(tokens))
			for _, tk := range tokens {
				set[tk] = struct{}{}
			}
			for _, group := range black {
				if allWordMatch(set, group) {
					return false
				}
			}
			if len(white) == 0 {
				return true
			}
			for _, group := range white {
				if allWordMatch(set, group) {
					return true
				}
			}
			return false
		}

	default: // "substring"
		return func(e Entry, raw string) bool {
			target := raw
			if s.SearchScope == "url" {
				target = e.URL
			}
			lt := strings.ToLower(target)
			for _, group := range black {
				if allSubstringMatch(lt, group) {
					return false
				}
			}
			if len(white) == 0 {
				return true
			}
			for _, group := range white {
				if allSubstringMatch(lt, group) {
					return true
				}
			}
			return false
		}
	}
}

func allSubstringMatch(target string, terms []string) bool {
	for _, t := range terms {
		if !strings.Contains(target, t) {
			return false
		}
	}
	return true
}

func allWordMatch(set map[string]struct{}, terms []string) bool {
	for _, t := range terms {
		if _, ok := set[t]; !ok {
			return false
		}
	}
	return true
}

func compileRegexGroups(groups [][]string) [][]*regexp.Regexp {
	result := make([][]*regexp.Regexp, 0, len(groups))
	for _, group := range groups {
		var regs []*regexp.Regexp
		for _, t := range group {
			if r, err := regexp.Compile(t); err == nil {
				regs = append(regs, r)
			}
		}
		if len(regs) > 0 {
			result = append(result, regs)
		}
	}
	return result
}

func allRegexMatch(target string, regs []*regexp.Regexp) bool {
	for _, r := range regs {
		if !r.MatchString(target) {
			return false
		}
	}
	return true
}

// ==============================
// Comparator + Dedupe
// ==============================

func less(a, b Entry) bool {
	if a.URL != b.URL {
		return a.URL < b.URL
	}
	return a.Timestamp.Before(b.Timestamp)
}

func entriesEqual(a, b Entry) bool {
	return a.ResponseType == b.ResponseType &&
		a.Date == b.Date &&
		a.Time == b.Time &&
		a.URL == b.URL &&
		a.Reason == b.Reason
}

// ==============================
// Logic
// ==============================

func processLogLine(
	line string,
	prev *Entry,
	matcher termMatcher,
	s Settings,
	errWriter *lazyErrWriter,
	stats *Stats,
) (*Entry, *Entry) {
	entry := parseLine(line)
	original := strings.TrimSpace(line)

	if entry.Malformed {
		stats.Malformed++
		if entry.Reason != "" {
			errWriter.writeString("URL_REJECTED (" + entry.Reason + "): " + original + "\n")
		} else {
			errWriter.writeString("MALFORMED_LINE: " + original + "\n")
		}
		return nil, prev
	}

	if !matcher(entry, line) {
		stats.Filtered++
		return nil, prev
	}

	if !s.KeepIFSRows && entry.ResponseType == "IFS" {
		stats.Filtered++
		return nil, prev
	}

	if s.MergeMatchedReasonLines && entry.ResponseType == "Reason" && prev != nil && !prev.Malformed {
		diff := entry.Timestamp.Sub(prev.Timestamp)
		if abs(diff.Seconds()) <= float64(s.ReasonLinkWindowSeconds) && entry.URL == prev.URL {
			if prev.ResponseType == "No" {
				prev.Reason = entry.Reason
				return nil, prev
			}
			if prev.ResponseType == "Yes" {
				return nil, prev
			}
		}
	}

	if entry.ResponseType == "Reason" && !s.KeepUnmatchedReasonLines {
		stats.Filtered++
		return nil, prev
	}

	return prev, &entry
}

// ==============================
// Processing
// ==============================

func processLogs(s Settings) error {
	if err := os.MkdirAll(s.OutputDir, 0755); err != nil {
		return fmt.Errorf("cannot create output directory: %w", err)
	}

	outputPath := filepath.Join(s.OutputDir, fmt.Sprintf("%s.%s", s.OutputFileName, s.OutputFormat))
	errorPath := filepath.Join(s.OutputDir, s.ErrorFile)
	processedPath := filepath.Join(s.OutputDir, "processed_logs.txt")

	outputMissing := !fileExists(outputPath)
	clearState := s.SortOutput || s.ProcessingMode == "overwrite" || outputMissing
	var processed map[string]bool
	if clearState {
		_ = os.Remove(outputPath)
		_ = os.Remove(processedPath)
		processed = map[string]bool{}
	} else {
		processed = readProcessedFiles(processedPath)
	}

	if s.SortOutput && s.ProcessingMode == "append" {
		fmt.Println("Note: sort_output = True reprocesses all log files each run.")
	}

	logFiles, err := listLogFiles(s.LogDir)
	if err != nil {
		return fmt.Errorf("log directory not found or unreadable (%s): %w", s.LogDir, err)
	}

	var filesToProcess []string
	for _, f := range logFiles {
		if !processed[f] {
			filesToProcess = append(filesToProcess, f)
		}
	}

	fmt.Printf("Found %d total log(s); processing %d new log(s).\n", len(logFiles), len(filesToProcess))
	if len(filesToProcess) == 0 {
		fmt.Println("Nothing to process.")
		return nil
	}

	errWriter := &lazyErrWriter{path: errorPath}
	defer errWriter.close()

	matcher := buildMatcher(s)
	stats := &Stats{}

	buffer := make([]Entry, 0, s.ChunkSize)
	var chunkFiles []string
	var chunkIndex int
	var nextIndex int64

	var streamWriter entryWriter
	if !s.SortOutput {
		streamWriter, err = newStreamWriter(outputPath, s)
		if err != nil {
			return fmt.Errorf("opening output: %w", err)
		}
	}
	defer func() {
		if streamWriter != nil {
			_ = streamWriter.close()
		}
	}()

	for fi, fname := range filesToProcess {
		fmt.Printf("Processing file %d/%d: %s\n", fi+1, len(filesToProcess), fname)

		filePath := filepath.Join(s.LogDir, fname)
		f, ferr := os.Open(filePath)
		if ferr != nil {
			fmt.Println("  Error opening file:", ferr)
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

		var prev *Entry
		var prevLineNumber int64
		lineCount := 0
		spinIndex := 0

		for scanner.Scan() {
			line := scanner.Text()
			lineCount++

			entryToAppend, newPrev := processLogLine(line, prev, matcher, s, errWriter, stats)

			if lineCount%5000 == 0 {
				fmt.Printf("\r[%c] %s — %d lines processed", spinner(spinIndex), fname, lineCount)
				spinIndex++
			}

			if entryToAppend != nil {
				entryToAppend.Index = nextIndex
				nextIndex++
				if s.IncludeFileLineRef {
					entryToAppend.FileName = fname
					entryToAppend.LineNumber = prevLineNumber
				}
				if s.SortOutput {
					buffer = append(buffer, *entryToAppend)
					if len(buffer) >= s.ChunkSize {
						path, cerr := writeChunk(buffer, chunkIndex, s.OutputDir)
						if cerr != nil {
							_ = f.Close()
							return cerr
						}
						chunkFiles = append(chunkFiles, path)
						chunkIndex++
						buffer = buffer[:0]
					}
				} else {
					if werr := streamWriter.writeEntry(*entryToAppend); werr != nil {
						_ = f.Close()
						return werr
					}
					stats.Written++
				}
			}

			prev = newPrev
			if newPrev != nil {
				prevLineNumber = int64(lineCount)
			} else {
				prevLineNumber = 0
			}
		}

		// flush the held prev entry at end of file
		if prev != nil {
			prev.Index = nextIndex
			nextIndex++
			if s.IncludeFileLineRef {
				prev.FileName = fname
				prev.LineNumber = prevLineNumber
			}
			if s.SortOutput {
				buffer = append(buffer, *prev)
			} else {
				if werr := streamWriter.writeEntry(*prev); werr != nil {
					_ = f.Close()
					return werr
				}
				stats.Written++
			}
		}

		fmt.Printf("\r[✓] %s — %d lines processed\n", fname, lineCount)
		_ = f.Close()

		if !s.SortOutput {
			appendProcessedFile(processedPath, fname)
		}
	}

	if s.SortOutput {
		if len(buffer) > 0 {
			path, cerr := writeChunk(buffer, chunkIndex, s.OutputDir)
			if cerr != nil {
				return cerr
			}
			chunkFiles = append(chunkFiles, path)
		}
		if len(chunkFiles) > 0 {
			if merr := mergeChunks(chunkFiles, s, outputPath, stats); merr != nil {
				return merr
			}
		}
		// mark all files processed only after a successful merge
		for _, fname := range filesToProcess {
			appendProcessedFile(processedPath, fname)
		}
	}

	fmt.Printf("\nProcessing complete.\n")
	fmt.Printf("  Written:   %d\n", stats.Written)
	fmt.Printf("  Filtered:  %d\n", stats.Filtered)
	fmt.Printf("  Malformed: %d\n", stats.Malformed)
	if s.SortOutput {
		fmt.Printf("  Duplicates removed: %d\n", stats.Duplicates)
	}
	return nil
}

// ==============================
// Chunk writing
// ==============================

func writeChunk(buffer []Entry, chunkIndex int, dir string) (string, error) {
	sort.Slice(buffer, func(i, j int) bool {
		return less(buffer[i], buffer[j])
	})
	path := filepath.Join(dir, fmt.Sprintf("chunk_%04d.tmp", chunkIndex))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	for _, e := range buffer {
		if err := w.Write(entryToChunkRow(e)); err != nil {
			return "", err
		}
	}
	w.Flush()
	return path, w.Error()
}

func entryToChunkRow(e Entry) []string {
	return []string{
		e.ResponseType,
		e.Date,
		e.Time,
		e.URL,
		e.Reason,
		e.Timestamp.Format(time.RFC3339Nano),
		strconv.FormatInt(e.Index, 10),
		e.FileName,
		strconv.FormatInt(e.LineNumber, 10),
	}
}

func chunkRowToEntry(row []string) (Entry, error) {
	if len(row) < 9 {
		return Entry{}, fmt.Errorf("short chunk row: %d fields", len(row))
	}
	ts, err := time.Parse(time.RFC3339Nano, row[5])
	if err != nil {
		return Entry{}, fmt.Errorf("bad timestamp in chunk: %w", err)
	}
	idx, _ := strconv.ParseInt(row[6], 10, 64)
	ln, _ := strconv.ParseInt(row[8], 10, 64)
	return Entry{
		ResponseType: row[0],
		Date:         row[1],
		Time:         row[2],
		URL:          row[3],
		Reason:       row[4],
		Timestamp:    ts,
		Index:        idx,
		FileName:     row[7],
		LineNumber:   ln,
	}, nil
}

// ==============================
// Heap merge
// ==============================

type heapItem struct {
	entry  Entry
	reader *csv.Reader
}

type chunkHeap []*heapItem

func (h chunkHeap) Len() int            { return len(h) }
func (h chunkHeap) Less(i, j int) bool  { return less(h[i].entry, h[j].entry) }
func (h chunkHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *chunkHeap) Push(x interface{}) { *h = append(*h, x.(*heapItem)) }
func (h *chunkHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return x
}

func mergeChunks(chunkFiles []string, s Settings, outputPath string, stats *Stats) error {
	var openFiles []*os.File
	defer func() {
		for _, f := range openFiles {
			_ = f.Close()
		}
		for _, path := range chunkFiles {
			_ = os.Remove(path)
		}
	}()

	h := &chunkHeap{}
	heap.Init(h)

	for _, path := range chunkFiles {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		openFiles = append(openFiles, f)
		r := csv.NewReader(f)
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			continue
		}
		if err != nil {
			return err
		}
		e, err := chunkRowToEntry(row)
		if err != nil {
			return err
		}
		heap.Push(h, &heapItem{entry: e, reader: r})
	}

	writer, err := newMergeWriter(outputPath, s)
	if err != nil {
		return err
	}

	var prev *Entry
	var mergeErr error
	for h.Len() > 0 {
		item := heap.Pop(h).(*heapItem)
		e := item.entry

		if prev == nil || !entriesEqual(*prev, e) {
			if werr := writer.writeEntry(e); werr != nil {
				mergeErr = werr
				break
			}
			stats.Written++
			eCopy := e
			prev = &eCopy
		} else {
			stats.Duplicates++
		}

		row, rerr := item.reader.Read()
		if errors.Is(rerr, io.EOF) {
			continue
		}
		if rerr != nil {
			mergeErr = rerr
			break
		}
		next, nerr := chunkRowToEntry(row)
		if nerr != nil {
			mergeErr = nerr
			break
		}
		item.entry = next
		heap.Push(h, item)
	}

	if mergeErr != nil {
		_ = writer.close()
		_ = os.Remove(outputPath)
		return mergeErr
	}
	return writer.close()
}

// ==============================
// Output writers
// ==============================

type entryWriter interface {
	writeEntry(e Entry) error
	close() error
}

// — CSV —

type csvEntryWriter struct {
	f *os.File
	w *csv.Writer
	s Settings
}

func newCSVEntryWriter(path string, s Settings) (*csvEntryWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := csv.NewWriter(f)
	if err := w.Write(csvHeader(s)); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &csvEntryWriter{f: f, w: w, s: s}, nil
}

func newCSVStreamWriter(path string, s Settings) (*csvEntryWriter, error) {
	exists := fileExists(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	w := csv.NewWriter(f)
	if !exists {
		if err := w.Write(csvHeader(s)); err != nil {
			_ = f.Close()
			return nil, err
		}
		w.Flush()
	}
	return &csvEntryWriter{f: f, w: w, s: s}, nil
}

func csvHeader(s Settings) []string {
	h := []string{"response_type", "date", "time", "url", "reason", "timestamp", "index"}
	if s.IncludeFileLineRef {
		h = append(h, "file_name", "line_number")
	}
	return h
}

func (c *csvEntryWriter) writeEntry(e Entry) error {
	row := []string{
		e.ResponseType, e.Date, e.Time, e.URL, e.Reason,
		e.Timestamp.Format(time.RFC3339Nano),
		strconv.FormatInt(e.Index, 10),
	}
	if c.s.IncludeFileLineRef {
		row = append(row, e.FileName, strconv.FormatInt(e.LineNumber, 10))
	}
	return c.w.Write(row)
}

func (c *csvEntryWriter) close() error {
	c.w.Flush()
	if err := c.w.Error(); err != nil {
		_ = c.f.Close()
		return err
	}
	return c.f.Close()
}

// — Parquet —

type parquetEntryWriter struct {
	f     *os.File
	w     *parquet.GenericWriter[ParquetRow]
	s     Settings
	batch []ParquetRow
}

func newParquetEntryWriter(path string, s Settings) (*parquetEntryWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := parquet.NewGenericWriter[ParquetRow](f, parquet.Compression(&zstd.Codec{}))
	return &parquetEntryWriter{f: f, w: w, s: s}, nil
}

func (p *parquetEntryWriter) writeEntry(e Entry) error {
	row := ParquetRow{
		ResponseType: e.ResponseType, Date: e.Date, Time: e.Time,
		URL: e.URL, Reason: e.Reason, Timestamp: e.Timestamp, Index: e.Index,
	}
	if p.s.IncludeFileLineRef {
		row.FileName = e.FileName
		row.LineNumber = e.LineNumber
	}
	p.batch = append(p.batch, row)
	if len(p.batch) >= 10_000 {
		return p.flush()
	}
	return nil
}

func (p *parquetEntryWriter) flush() error {
	if len(p.batch) == 0 {
		return nil
	}
	_, err := p.w.Write(p.batch)
	p.batch = p.batch[:0]
	return err
}

func (p *parquetEntryWriter) close() error {
	if err := p.flush(); err != nil {
		_ = p.w.Close()
		_ = p.f.Close()
		return err
	}
	if err := p.w.Close(); err != nil {
		_ = p.f.Close()
		return err
	}
	return p.f.Close()
}

// — Routing —

func newMergeWriter(path string, s Settings) (entryWriter, error) {
	if s.OutputFormat == "parquet" {
		return newParquetEntryWriter(path, s)
	}
	return newCSVEntryWriter(path, s)
}

func newStreamWriter(path string, s Settings) (entryWriter, error) {
	if s.OutputFormat == "parquet" {
		if fileExists(path) {
			fmt.Println("Note: Parquet output does not support append — existing file will be overwritten.")
		}
		return newParquetEntryWriter(path, s)
	}
	return newCSVStreamWriter(path, s)
}

// ==============================
// Lazy error writer
// ==============================

type lazyErrWriter struct {
	path string
	f    *os.File
	w    *bufio.Writer
}

func (l *lazyErrWriter) writeString(s string) {
	if l.f == nil {
		f, err := os.Create(l.path)
		if err != nil {
			return
		}
		l.f = f
		l.w = bufio.NewWriter(f)
	}
	_, _ = l.w.WriteString(s)
}

func (l *lazyErrWriter) close() {
	if l.f != nil {
		_ = l.w.Flush()
		_ = l.f.Close()
	}
}

// ==============================
// Helpers
// ==============================

func listLogFiles(dir string) ([]string, error) {
	var files []string
	reg := regexp.MustCompile(LogFilenamePattern)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() && reg.MatchString(e.Name()) {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}

func readProcessedFiles(path string) map[string]bool {
	result := map[string]bool{}
	f, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(f), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result[line] = true
		}
	}
	return result
}

func appendProcessedFile(path, name string) {
	f, _ := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	_, _ = f.WriteString(name + "\n")
	_ = f.Close()
}

func defaultIfEmpty(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

var spinnerChars = []rune{'-', '\\', '|', '/'}

func spinner(i int) rune {
	return spinnerChars[i%len(spinnerChars)]
}
