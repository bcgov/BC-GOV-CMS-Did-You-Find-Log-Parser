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
	LogDir              string
	OutputDir           string
	SearchTerms         []string
	ProcessingMode      string
	CleanAfter          bool
	MaxMemoryMB         int
	ChunkSize           int
	LogLevel            string
	ErrorFile           string
	OutputFileName      string
	OutputFormat        string
	StrictURLMode       bool
	AllowedHosts        []string
	AllowedPathPrefixes []string

	// New/updated behavior toggles
	ReconcileReason         bool
	IncludeReasonRows       bool
	ReasonLinkWindowSeconds int
	SearchScope             string // "url" | "full_line"
	SearchMode              string // "substring" | "word" | "regex"
	SortOutput              bool
}

type Entry struct {
	ResponseType string
	Date         string
	Time         string
	URL          string
	Reason       string
	Timestamp    time.Time
	Malformed    bool
}

type ParquetRow struct {
	ResponseType string    `parquet:"response_type"`
	Date         string    `parquet:"date"`
	Time         string    `parquet:"time"`
	URL          string    `parquet:"url"`
	Reason       string    `parquet:"reason"`
	Timestamp    time.Time `parquet:"timestamp,logical=timestamp,unit=us"`
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

		// 1. Log Folder
		fmt.Print("Enter the folder where log files are located (default: logs): ")
		logDirInput, _ := reader.ReadString('\n')
		logDir := strings.TrimSpace(logDirInput)
		if logDir == "" {
			logDir = "logs"
		}

		// 2. Output Folder
		fmt.Print("Enter the folder where processed output should be saved (default: output): ")
		outDirInput, _ := reader.ReadString('\n')
		outDir := strings.TrimSpace(outDirInput)
		if outDir == "" {
			outDir = "output"
		}

		// 3. Search Terms
		fmt.Print("Enter comma-separated search terms (leave blank for none): ")
		termsInput, _ := reader.ReadString('\n')
		terms := strings.TrimSpace(termsInput)

		// Build full config file contents
		content := fmt.Sprintf(`# Configuration file for Did-You-Find log processing
[Paths]
log_file_archive = %s
output_directory = %s

[Processing]
search_terms = %s
clean_after = True
max_memory_mb = 1024
chunk_size = 100000
log_level = Info
error_log_file = error_log.txt
strict_url_mode = False
allowed_hosts = www2.gov.bc.ca
allowed_path_prefixes = /gov/content/

; Safer defaults
reconcile_reason = False
include_reason_rows = True
reason_link_window_seconds = 60
search_scope = url
search_mode = word

; Sorting on by default
sort_output = True

[Output]
output_file_name = Did-You-Find-Log
output_format = csv
`, logDir, outDir, terms)

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
	maxMB, _ := strconv.Atoi(defaultIfEmpty(get("max_memory_mb"), "1024"))
	clean := strings.ToLower(get("clean_after")) == "true"
	strict := strings.ToLower(get("strict_url_mode")) == "true"
	allowedHosts := splitComma(get("allowed_hosts"))
	allowedPrefixes := splitComma(get("allowed_path_prefixes"))

	// New flags with safe defaults
	reconcile := strings.ToLower(get("reconcile_reason")) == "true"
	includeReason := strings.ToLower(get("include_reason_rows")) != "false" // default true
	linkWindow, _ := strconv.Atoi(defaultIfEmpty(get("reason_link_window_seconds"), "60"))

	searchScope := strings.ToLower(defaultIfEmpty(get("search_scope"), "url"))
	if searchScope != "url" && searchScope != "full_line" {
		searchScope = "url"
	}
	searchMode := strings.ToLower(defaultIfEmpty(get("search_mode"), "word"))
	if searchMode != "substring" && searchMode != "word" && searchMode != "regex" {
		searchMode = "word"
	}

	sortOutput := strings.ToLower(defaultIfEmpty(get("sort_output"), "true")) == "true"

	return Settings{
		LogDir:              get("log_file_archive"),
		OutputDir:           get("output_directory"),
		SearchTerms:         splitComma(get("search_terms")),
		ProcessingMode:      strings.ToLower(get("processing_mode")),
		CleanAfter:          clean,
		MaxMemoryMB:         maxMB,
		ChunkSize:           chunk,
		LogLevel:            get("log_level"),
		ErrorFile:           get("error_log_file"),
		OutputFileName:      get("output_file_name"),
		OutputFormat:        strings.ToLower(get("output_format")),
		StrictURLMode:       strict,
		AllowedHosts:        allowedHosts,
		AllowedPathPrefixes: allowedPrefixes,

		ReconcileReason:         reconcile,
		IncludeReasonRows:       includeReason,
		ReasonLinkWindowSeconds: linkWindow,
		SearchScope:             searchScope,
		SearchMode:              searchMode,
		SortOutput:              sortOutput,
	}, nil
}

// ==============================
// Parsing
// ==============================

func parseLine(line string, s Settings) Entry {
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

	// Strict-capable normalization + validation
	urlNorm, ok, reason := normalizeURL(parts[3], s)
	if !ok {
		e.Malformed = true
		e.Reason = reason
		return e
	}
	e.URL = urlNorm

	// Optional reason token (survey reason)
	if len(parts) > 4 {
		last := parts[len(parts)-1]
		if validReasons[last] {
			e.Reason = last
		} else if e.ResponseType == "Reason" {
			// Keep the row; just no canned reason recognized
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
func normalizeURL(raw string, s Settings) (string, bool, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, "EmptyOrInvalidURL"
	}

	// Remove query and fragment (canonicalize to path only)
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

	// Prefer https in strict mode
	if s.StrictURLMode {
		if !strings.EqualFold(u.Scheme, "https") {
			return "", false, "SchemeNotAllowed"
		}
	}

	// Lowercase scheme and host
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// Normalize path: collapse repeated slashes
	path := u.EscapedPath()
	needsCollapse := strings.Contains(path, "//")
	path = collapseSlashes(path)

	// Detect ellipsis / truncation (literal … or percent-encoded)
	lp := strings.ToLower(path)
	if strings.Contains(path, "…") || strings.Contains(lp, "%e2%80%a6") {
		if s.StrictURLMode {
			return "", false, "LikelyTruncated"
		}
		// relaxed mode: allow through
	}

	// Trim trailing slash, except root
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}

	// Validate UTF-8
	if !utf8.ValidString(path) {
		return "", false, "EmptyOrInvalidURL"
	}

	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""

	// Host allowlist (strict)
	if s.StrictURLMode && len(s.AllowedHosts) > 0 {
		allowed := false
		for _, h := range s.AllowedHosts {
			if strings.EqualFold(u.Host, strings.TrimSpace(h)) {
				allowed = true
				break
			}
		}
		if !allowed {
			if strings.Contains(u.Host, "translate.goog") {
				return "", false, "MachineTranslatedMirror"
			}
			return "", false, "HostNotAllowed"
		}
	}

	// Path allowlist (strict) with boundary check
	if s.StrictURLMode && len(s.AllowedPathPrefixes) > 0 {
		allowed := false
		lowerPath := strings.ToLower(u.Path)
		for _, p := range s.AllowedPathPrefixes {
			p = strings.TrimSpace(strings.ToLower(p))
			if p == "" {
				continue
			}
			if hasPathPrefix(lowerPath, p) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", false, "PatternNotAllowed"
		}
	}

	// If we had to collapse multiple slashes, choose strict policy
	if needsCollapse && s.StrictURLMode {
		return "", false, "MalformedPath"
	}

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

// hasPathPrefix ensures prefix matches on a segment boundary
func hasPathPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if len(path) == len(prefix) {
		return true
	}
	return path[len(prefix)] == '/'
}

// ==============================
// Matching / Filtering
// ==============================

type termMatcher func(entry Entry, rawLine string) bool

func buildMatcher(s Settings) termMatcher {
	terms := s.SearchTerms
	if len(terms) == 0 {
		return func(_ Entry, _ string) bool { return true } // no filtering
	}

	switch s.SearchMode {
	case "regex":
		regs := make([]*regexp.Regexp, 0, len(terms))
		for _, t := range terms {
			r, err := regexp.Compile(t)
			if err == nil {
				regs = append(regs, r)
			}
		}
		return func(e Entry, raw string) bool {
			target := raw
			if s.SearchScope == "url" {
				target = e.URL
			}
			lt := strings.ToLower(target)
			for _, r := range regs {
				if r.MatchString(lt) {
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
			set := map[string]struct{}{}
			for _, tk := range tokens {
				set[tk] = struct{}{}
			}
			for _, t := range terms {
				if _, ok := set[t]; ok {
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
			for _, t := range terms {
				if strings.Contains(lt, t) {
					return true
				}
			}
			return false
		}
	}
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
	entry := parseLine(line, s)
	original := strings.TrimSpace(line)

	if entry.Malformed {
		// Differentiate URL-based rejection from other malformed lines
		if entry.Reason != "" {
			errWriter.WriteString("URL_REJECTED (" + entry.Reason + "): " + original + "\n")
		} else {
			errWriter.WriteString("MALFORMED_LINE: " + original + "\n")
		}
		return nil, prev
	}

	// Filter now (respects search_scope/mode; default: URL only)
	if !matcher(entry, line) {
		return nil, prev
	}

	// Skip IFS
	if entry.ResponseType == "IFS" {
		return nil, prev
	}

	// OPTIONAL reconciliation (default OFF)
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

	// If not reconciling: keep Reason rows (unless IncludeReasonRows=false)
	if entry.ResponseType == "Reason" && !s.IncludeReasonRows {
		return nil, prev
	}

	return prev, &entry
}

// ==============================
// Processing log files
// ==============================

func processLogs(s Settings) error {
	// Ensure dirs
	_ = os.MkdirAll(s.OutputDir, 0755)

	outputPath := filepath.Join(s.OutputDir, fmt.Sprintf("%s.%s", s.OutputFileName, s.OutputFormat))
	errorPath := filepath.Join(s.OutputDir, s.ErrorFile)

	// If output file is missing, rebuild from scratch (even if processed_logs.txt exists)
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

	// Build matcher once
	matcher := buildMatcher(s)

	for fi, fname := range filesToProcess {
		fmt.Printf("Processing file %d/%d: %s\n", fi+1, len(filesToProcess), fname)
		filePath := filepath.Join(s.LogDir, fname)
		f, ferr := os.Open(filePath)
		if ferr != nil {
			fmt.Println("Error opening file:", ferr)
			continue
		}

		scanner := bufio.NewScanner(f)
		// Increase scanner buffer to accommodate long lines/URLs
		scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

		var prev *Entry
		lineCount := 0
		spinIndex := 0

		for scanner.Scan() {
			line := scanner.Text()
			entryToAppend, newPrev := processLogLine(line, prev, matcher, s, bufErr)
			lineCount++
			if lineCount%5000 == 0 { // update ~every 5k lines
				fmt.Printf("\r[%c] %s — %d lines processed", spinner(spinIndex), fname, lineCount)
				spinIndex++
			}
			if entryToAppend != nil {
				buffer = append(buffer, *entryToAppend)
			}
			if len(buffer) >= s.ChunkSize {
				parquetWriter, err = flushBuffer(buffer, s, outputPath, parquetWriter)
				if err != nil {
					return err
				}
				buffer = buffer[:0]
			}
			prev = newPrev
		}

		// flush last entry for this file
		if prev != nil {
			buffer = append(buffer, *prev)
		}

		// finalize display for this file
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
	// Default to CSV if unexpected format
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
		_ = w.Write([]string{"response_type", "date", "time", "url", "reason", "timestamp"})
	}
	for _, e := range buffer {
		_ = w.Write([]string{
			e.ResponseType,
			e.Date,
			e.Time,
			e.URL,
			e.Reason,
			e.Timestamp.Format(time.RFC3339Nano),
		})
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
	// Init on first write
	if gw == nil {
		f, err := os.Create(outputPath)
		if err != nil {
			return nil, err
		}
		// Keep the file handle open; parquet-go writer manages it
		gw = parquet.NewGenericWriter[ParquetRow](f, parquet.Compression(&zstd.Codec{}))

	}

	// Write each row (you can batch if you prefer)
	for _, e := range buffer {
		row := ParquetRow{
			ResponseType: e.ResponseType,
			Date:         e.Date,
			Time:         e.Time,
			URL:          e.URL,
			Reason:       e.Reason,
			Timestamp:    e.Timestamp,
		}
		if _, err := gw.Write([]ParquetRow{row}); err != nil {
			return gw, err
		}
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
	seen := map[string]bool{}
	uniq := make([][]string, 0, len(data))

	for _, row := range data {
		// dedupe key: response_type, date, time, url, reason
		if len(row) < 6 {
			continue
		}
		key := strings.Join(row[:5], "\n")
		if !seen[key] {
			seen[key] = true
			uniq = append(uniq, row)
		}
	}

	// Optional sort (default true): by url (3), date (1), time (2)
	if s.SortOutput {
		sort.Slice(uniq, func(i, j int) bool {
			ui, uj := uniq[i], uniq[j]
			if ui[3] != uj[3] {
				return ui[3] < uj[3]
			}
			if ui[1] != uj[1] {
				return ui[1] < uj[1]
			}
			return ui[2] < uj[2]
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
	// Open parquet file for reading
	f, err := os.Open(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := parquet.NewGenericReader[ParquetRow](f)
	dedupe := make(map[string]ParquetRow)

	// Read in batches
	const batchSize = 10_000
	for {
		rows := make([]ParquetRow, batchSize)
		n, err := reader.Read(rows)
		if n > 0 {
			for _, row := range rows[:n] {
				// Validate timestamp
				if row.Timestamp.IsZero() {
					continue
				}
				// Dedupe key (same as CSV)
				key := strings.Join([]string{
					row.ResponseType,
					row.Date,
					row.Time,
					row.URL,
					row.Reason,
				}, "\n")
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

	// Prepare to write cleaned file to temp, then replace
	tmpPath := outputPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer out.Close()

	writer := parquet.NewGenericWriter[ParquetRow](out, parquet.Compression(&zstd.Codec{}))
	// Convert map → slice
	cleanedRows := make([]ParquetRow, 0, len(dedupe))
	for _, r := range dedupe {
		cleanedRows = append(cleanedRows, r)
	}

	// Optional sort (default true)
	if s.SortOutput {
		sort.Slice(cleanedRows, func(i, j int) bool {
			if cleanedRows[i].URL != cleanedRows[j].URL {
				return cleanedRows[i].URL < cleanedRows[j].URL
			}
			if cleanedRows[i].Date != cleanedRows[j].Date {
				return cleanedRows[i].Date < cleanedRows[j].Date
			}
			return cleanedRows[i].Time < cleanedRows[j].Time
		})
	}

	// Write in chunks
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

	// Replace original file with cleaned file
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return err
	}
	return nil
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

var spinnerChars = []rune{'-', '/', '-', '\\'} // ASCII-safe spinner

func spinner(i int) rune {
	return spinnerChars[i%len(spinnerChars)]
}
