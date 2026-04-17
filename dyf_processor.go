package main

import (
	"bufio"
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
	ProcessedLogsFile  = "processed_logs.txt"
	DefaultChunkSize   = 100000
	TimestampLayout    = "2006-01-02 15:04:05"
	LogFilenamePattern = `^\d{4}-\d{2}\.log$`
)

// ==============================
// Settings / Models
// ==============================

type Settings struct {
	LogDir         string
	OutputDir      string
	WhiteList      [][]string // OR of AND groups: [[a,b],[c,d]] = (a AND b) OR (c AND d)
	BlackList      [][]string
	ProcessingMode string
	CleanAfter     bool
	ChunkSize      int
	LogLevel       string
	ErrorFile      string
	OutputFileName string
	OutputFormat   string
	// Behavior toggles
	ReconcileReason         bool
	IncludeReasonRows       bool
	ReasonLinkWindowSeconds int
	SearchScope             string // "url" | "full_line"
	SearchMode              string // "substring" | "word" | "regex"
	SortOutput              bool
	IncludeFileLineRef      bool
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
	ensureConfig()
	settings, err := loadConfig()
	if err != nil {
		fmt.Println("Error loading config:", err)
		return
	}
	fmt.Println("\nLoaded configuration:")
	fmt.Printf("%+v\n", settings)
	if err := processLogs(settings); err != nil {
		fmt.Println("Processing error:", err)
	}
}

// ==============================
// Config
// ==============================

func ensureConfig() {
	if _, err := os.Stat(ConfigFile); errors.Is(err, os.ErrNotExist) {
		fmt.Println("No config.ini found. Let's set up your configuration.")
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Enter the folder where log files are located (default: logs): ")
		logDirInput, _ := reader.ReadString('\n')
		logDir := strings.TrimSpace(logDirInput)
		if logDir == "" {
			logDir = "logs"
		}

		fmt.Print("Enter the folder where processed output should be saved (default: output): ")
		outDirInput, _ := reader.ReadString('\n')
		outDir := strings.TrimSpace(outDirInput)
		if outDir == "" {
			outDir = "output"
		}

		fmt.Print("Enter comma-separated white list terms (leave blank for none): ")
		whiteInput, _ := reader.ReadString('\n')
		white := strings.TrimSpace(whiteInput)

		content := fmt.Sprintf(`# Configuration file for Did-You-Find log processing
[Paths]
log_file_archive = %s
output_directory = %s

[Processing]
; white_list: URL must satisfy at least one group (leave blank to include all URLs)
; black_list: URL is excluded if it satisfies any group (leave blank to exclude nothing)
;
; Syntax: use AND within a group, OR between groups, parentheses to define groups clearly.
;   Single term:      white_list = taxes
;   AND group:        white_list = (taxes AND /gov/content/taxes)
;   Multiple groups:  white_list = (taxes AND /gov/content/taxes) OR (transportation AND cars)
;   Black list:       black_list = (/test/) OR (/staging/)
white_list = %s
black_list =
clean_after = True
chunk_size = 100000
log_level = Info
error_log_file = error_log.txt

; Behavior toggles
reconcile_reason = False
include_reason_rows = True
reason_link_window_seconds = 60

; Search behavior (applies to both white_list and black_list)
; search_scope: "url" matches only the URL; "full_line" matches the entire log line
; search_mode:  "substring" | "word" | "regex"
search_scope = url
search_mode = substring

; Sorting: False preserves original sequence; True sorts by url then index
sort_output = False

; Optional source references in output (CSV adds columns only when true; Parquet always has columns)
include_file_line_ref = False

[Output]
output_file_name = Did-You-Find-Log
output_format = csv
`, logDir, outDir, white)

		err := os.WriteFile(ConfigFile, []byte(content), 0644)
		if err != nil {
			fmt.Println("Error creating config.ini:", err)
			return
		}
		fmt.Println("\nConfig file created: config.ini")
		fmt.Println("Please review and customize other settings if needed.")
	} else {
		fmt.Println("Config file found:", ConfigFile)
	}
}

func loadConfig() (Settings, error) {
	raw, err := os.ReadFile(ConfigFile)
	if err != nil {
		return Settings{}, err
	}
	lines := strings.Split(string(raw), "\n")
	get := func(key string) string {
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), key+" =") {
				return strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
			}
		}
		return ""
	}
	chunk, _ := strconv.Atoi(defaultIfEmpty(get("chunk_size"), "100000"))
	clean := strings.ToLower(get("clean_after")) == "true"

	reconcile := strings.ToLower(get("reconcile_reason")) == "true"
	includeReason := strings.ToLower(get("include_reason_rows")) != "false"
	linkWindow, _ := strconv.Atoi(defaultIfEmpty(get("reason_link_window_seconds"), "60"))

	searchScope := strings.ToLower(defaultIfEmpty(get("search_scope"), "url"))
	if searchScope != "url" && searchScope != "full_line" {
		searchScope = "url"
	}
	searchMode := strings.ToLower(defaultIfEmpty(get("search_mode"), "substring"))
	if searchMode != "substring" && searchMode != "word" && searchMode != "regex" {
		searchMode = "substring"
	}

	sortOutput := strings.ToLower(defaultIfEmpty(get("sort_output"), "false")) == "true"
	includeFileLineRef := strings.ToLower(defaultIfEmpty(get("include_file_line_ref"), "false")) == "true"

	return Settings{
		LogDir:                  get("log_file_archive"),
		OutputDir:               get("output_directory"),
		WhiteList:               parseFilterExpression(get("white_list")),
		BlackList:               parseFilterExpression(get("black_list")),
		ProcessingMode:          strings.ToLower(get("processing_mode")),
		CleanAfter:              clean,
		ChunkSize:               chunk,
		LogLevel:                get("log_level"),
		ErrorFile:               get("error_log_file"),
		OutputFileName:          get("output_file_name"),
		OutputFormat:            strings.ToLower(get("output_format")),
		ReconcileReason:         reconcile,
		IncludeReasonRows:       includeReason,
		ReasonLinkWindowSeconds: linkWindow,
		SearchScope:             searchScope,
		SearchMode:              searchMode,
		SortOutput:              sortOutput,
		IncludeFileLineRef:      includeFileLineRef,
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

// normalizeURL returns (normalizedURL, ok, reasonIfRejected)
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

// parseFilterExpression parses a white_list or black_list config value into OR-of-AND groups.
// Syntax: (term1 AND term2) OR (term3 AND term4)
// Parentheses are optional for single terms or single groups.
// Returns [][]string where the outer slice is OR'd and each inner slice is AND'd.
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
// Logic
// ==============================

func processLogLine(
	line string,
	prev *Entry,
	matcher termMatcher,
	s Settings,
	errWriter *bufio.Writer,
) (*Entry, *Entry) {
	entry := parseLine(line)
	original := strings.TrimSpace(line)

	if entry.Malformed {
		if entry.Reason != "" {
			errWriter.WriteString("URL_REJECTED (" + entry.Reason + "): " + original + "\n")
		} else {
			errWriter.WriteString("MALFORMED_LINE: " + original + "\n")
		}
		return nil, prev
	}

	if !matcher(entry, line) {
		return nil, prev
	}

	if entry.ResponseType == "IFS" {
		return nil, prev
	}

	if s.ReconcileReason && entry.ResponseType == "Reason" && prev != nil && !prev.Malformed {
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

	if entry.ResponseType == "Reason" && !s.IncludeReasonRows {
		return nil, prev
	}

	return prev, &entry
}

// ==============================
// Processing log files
// ==============================

func processLogs(s Settings) error {
	_ = os.MkdirAll(s.OutputDir, 0755)
	outputPath := filepath.Join(s.OutputDir, fmt.Sprintf("%s.%s", s.OutputFileName, s.OutputFormat))
	errorPath := filepath.Join(s.OutputDir, s.ErrorFile)

	outputMissing := !fileExists(outputPath)
	var processed map[string]bool
	var err error
	if s.ProcessingMode == "overwrite" || outputMissing {
		_ = os.Remove(outputPath)
		_ = os.Remove(ProcessedLogsFile)
		processed = map[string]bool{}
	} else {
		processed = readProcessedFiles()
	}

	logFiles, err := listLogFiles(s.LogDir)
	if err != nil {
		return err
	}

	var filesToProcess []string
	for _, f := range logFiles {
		if !processed[f] {
			filesToProcess = append(filesToProcess, f)
		}
	}

	fmt.Printf("Found %d total logs; processing %d new logs.\n", len(logFiles), len(filesToProcess))

	errFile, _ := os.Create(errorPath)
	bufErr := bufio.NewWriter(errFile)
	defer errFile.Close()

	buffer := make([]Entry, 0, s.ChunkSize)
	var parquetWriter *parquet.GenericWriter[ParquetRow]

	matcher := buildMatcher(s)

	var nextIndex int64 = 0

	for fi, fname := range filesToProcess {
		fmt.Printf("Processing file %d/%d: %s\n", fi+1, len(filesToProcess), fname)

		filePath := filepath.Join(s.LogDir, fname)
		f, ferr := os.Open(filePath)
		if ferr != nil {
			fmt.Println("Error opening file:", ferr)
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

		var prev *Entry
		var prevLineNumber int64 = 0
		lineCount := 0
		spinIndex := 0

		for scanner.Scan() {
			line := scanner.Text()
			lineCount++
			currentLineNumber := int64(lineCount)

			entryToAppend, newPrev := processLogLine(line, prev, matcher, s, bufErr)

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
				buffer = append(buffer, *entryToAppend)
			}

			prev = newPrev
			if newPrev != nil {
				prevLineNumber = currentLineNumber
			} else {
				prevLineNumber = 0
			}

			if len(buffer) >= s.ChunkSize {
				parquetWriter, err = flushBuffer(buffer, s, outputPath, parquetWriter)
				if err != nil {
					_ = f.Close()
					return err
				}
				buffer = buffer[:0]
			}
		}

		if prev != nil {
			prev.Index = nextIndex
			nextIndex++
			if s.IncludeFileLineRef {
				prev.FileName = fname
				prev.LineNumber = prevLineNumber
			}
			buffer = append(buffer, *prev)
		}

		fmt.Printf("\r[✓] %s — %d lines processed\n", fname, lineCount)

		_ = f.Close()
		appendProcessedFile(fname)
	}

	if len(buffer) > 0 {
		parquetWriter, err = flushBuffer(buffer, s, outputPath, parquetWriter)
		if err != nil {
			return err
		}
	}

	if parquetWriter != nil {
		if err := parquetWriter.Close(); err != nil {
			fmt.Println("Error closing parquet writer:", err)
		}
	}

	_ = bufErr.Flush()
	fmt.Println("Processing complete.")

	if s.CleanAfter {
		cleanOutput(outputPath, s.OutputFormat, s)
	}
	return nil
}

// ==============================
// Buffer writer
// ==============================

func flushBuffer(
	buffer []Entry,
	s Settings,
	outputFile string,
	gw *parquet.GenericWriter[ParquetRow],
) (*parquet.GenericWriter[ParquetRow], error) {
	switch s.OutputFormat {
	case "csv":
		return writeCSV(buffer, s, outputFile)
	case "parquet":
		return writeParquet(buffer, s, outputFile, gw)
	default:
		fmt.Println("Unknown output format:", s.OutputFormat, "— defaulting to CSV")
		return writeCSV(buffer, s, outputFile)
	}
}

// ==============================
// CSV output
// ==============================

func writeCSV(buffer []Entry, s Settings, outputPath string) (*parquet.GenericWriter[ParquetRow], error) {
	exists := fileExists(outputPath)

	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	w := csv.NewWriter(f)

	if !exists {
		base := []string{"response_type", "date", "time", "url", "reason", "timestamp", "index"}
		if s.IncludeFileLineRef {
			base = append(base, "file_name", "line_number")
		}
		_ = w.Write(base)
	}

	for _, e := range buffer {
		row := []string{
			e.ResponseType,
			e.Date,
			e.Time,
			e.URL,
			e.Reason,
			e.Timestamp.Format(time.RFC3339Nano),
			strconv.FormatInt(e.Index, 10),
		}
		if s.IncludeFileLineRef {
			row = append(row, e.FileName, strconv.FormatInt(e.LineNumber, 10))
		}
		_ = w.Write(row)
	}

	w.Flush()
	if err := w.Error(); err != nil {
		_ = f.Close()
		return nil, err
	}
	_ = f.Close()
	return nil, nil
}

// ==============================
// Parquet output
// ==============================

func writeParquet(
	buffer []Entry,
	s Settings,
	outputPath string,
	gw *parquet.GenericWriter[ParquetRow],
) (*parquet.GenericWriter[ParquetRow], error) {
	if gw == nil {
		f, err := os.Create(outputPath)
		if err != nil {
			return nil, err
		}
		gw = parquet.NewGenericWriter[ParquetRow](f, parquet.Compression(&zstd.Codec{}))
	}

	rows := make([]ParquetRow, 0, len(buffer))
	for _, e := range buffer {
		row := ParquetRow{
			ResponseType: e.ResponseType,
			Date:         e.Date,
			Time:         e.Time,
			URL:          e.URL,
			Reason:       e.Reason,
			Timestamp:    e.Timestamp,
			Index:        e.Index,
		}
		if s.IncludeFileLineRef {
			row.FileName = e.FileName
			row.LineNumber = e.LineNumber
		}
		rows = append(rows, row)
	}
	if _, err := gw.Write(rows); err != nil {
		return gw, err
	}
	return gw, nil
}

// ==============================
// Clean output (dedupe, optional sort)
// ==============================

func cleanOutput(outputPath, format string, s Settings) {
	fmt.Println("Cleaning final output... (dedupe + timestamp validation)")
	switch format {
	case "csv":
		if err := cleanCSV(outputPath, s); err != nil {
			fmt.Println("Error cleaning csv:", err)
		}
	case "parquet":
		fmt.Println("Cleaning parquet output...")
		if err := cleanParquet(outputPath, s); err != nil {
			fmt.Println("Error cleaning parquet:", err)
		}
	default:
		fmt.Println("Unknown output format:", format)
	}
}

func cleanCSV(path string, s Settings) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		return err
	}
	if len(rows) < 2 {
		return nil
	}

	header := rows[0]
	data := rows[1:]

	hIdx := map[string]int{}
	for i, name := range header {
		hIdx[strings.ToLower(strings.TrimSpace(name))] = i
	}
	idxRT, ok1 := hIdx["response_type"]
	idxDate, ok2 := hIdx["date"]
	idxTime, ok3 := hIdx["time"]
	idxURL, ok4 := hIdx["url"]
	idxReason, ok5 := hIdx["reason"]
	idxIndex, ok7 := hIdx["index"]

	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok7) {
		return fmt.Errorf("missing required columns in CSV header")
	}

	// Dedupe on (response_type, date, time, url, reason) — keep the lowest index
	type dedupedRow struct {
		row []string
		idx int64
	}
	dedupeMap := make(map[string]dedupedRow, len(data))

	for _, row := range data {
		if len(row) <= idxIndex {
			continue
		}
		key := strings.Join([]string{
			row[idxRT], row[idxDate], row[idxTime], row[idxURL], row[idxReason],
		}, "\n")

		idxVal, err := strconv.ParseInt(row[idxIndex], 10, 64)
		if err != nil {
			continue
		}

		if existing, ok := dedupeMap[key]; !ok || idxVal < existing.idx {
			dedupeMap[key] = dedupedRow{row: row, idx: idxVal}
		}
	}

	uniq := make([][]string, 0, len(dedupeMap))
	for _, dr := range dedupeMap {
		uniq = append(uniq, dr.row)
	}

	if s.SortOutput {
		sort.Slice(uniq, func(i, j int) bool {
			ui, uj := uniq[i], uniq[j]
			if ui[idxURL] != uj[idxURL] {
				return ui[idxURL] < uj[idxURL]
			}
			ii, _ := strconv.ParseInt(ui[idxIndex], 10, 64)
			ij, _ := strconv.ParseInt(uj[idxIndex], 10, 64)
			return ii < ij
		})
	}

	wf, err := os.Create(path)
	if err != nil {
		return err
	}
	defer wf.Close()

	w := csv.NewWriter(wf)
	if err := w.Write(header); err != nil {
		return err
	}
	w.WriteAll(uniq)
	w.Flush()
	return w.Error()
}

func cleanParquet(outputPath string, s Settings) error {
	f, err := os.Open(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := parquet.NewGenericReader[ParquetRow](f)
	dedupe := make(map[string]ParquetRow)

	const batchSize = 10_000
	for {
		rows := make([]ParquetRow, batchSize)
		n, err := reader.Read(rows)
		if n > 0 {
			for _, row := range rows[:n] {
				if row.Timestamp.IsZero() {
					continue
				}
				key := strings.Join([]string{
					row.ResponseType,
					row.Date,
					row.Time,
					row.URL,
					row.Reason,
				}, "\n")

				if existing, ok := dedupe[key]; ok {
					if row.Index >= existing.Index {
						continue
					}
				}
				dedupe[key] = row
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = reader.Close()
			return err
		}
	}
	_ = reader.Close()

	tmpPath := outputPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer out.Close()

	writer := parquet.NewGenericWriter[ParquetRow](out, parquet.Compression(&zstd.Codec{}))

	cleanedRows := make([]ParquetRow, 0, len(dedupe))
	for _, r := range dedupe {
		cleanedRows = append(cleanedRows, r)
	}

	if s.SortOutput {
		sort.Slice(cleanedRows, func(i, j int) bool {
			if cleanedRows[i].URL != cleanedRows[j].URL {
				return cleanedRows[i].URL < cleanedRows[j].URL
			}
			return cleanedRows[i].Index < cleanedRows[j].Index
		})
	}

	for len(cleanedRows) > 0 {
		chunk := cleanedRows
		if len(chunk) > 10_000 {
			chunk = cleanedRows[:10_000]
		}
		if _, err := writer.Write(chunk); err != nil {
			_ = writer.Close()
			return err
		}
		cleanedRows = cleanedRows[len(chunk):]
	}

	if err := writer.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, outputPath)
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

func readProcessedFiles() map[string]bool {
	result := map[string]bool{}
	f, err := os.ReadFile(ProcessedLogsFile)
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

func appendProcessedFile(name string) {
	f, _ := os.OpenFile(ProcessedLogsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	_, _ = f.WriteString(name + "\n")
	_ = f.Close()
}

func splitComma(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0)
	for _, p := range parts {
		v := strings.TrimSpace(strings.ToLower(p))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
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

var spinnerChars = []rune{'-', '/', '-', '\\'}

func spinner(i int) rune {
	return spinnerChars[i%len(spinnerChars)]
}
