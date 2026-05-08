package persist

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// DumpCSVGz exports every `events` row older than cutoff to a gzipped
// CSV file at path. Returns the row count written. Caller is responsible
// for moving the file off-box (e.g. aws s3 cp) and for calling Trim to
// free the rows from SQLite.
//
// CSV + gzip was chosen over Parquet to avoid pulling a 15 MB parquet
// dependency for what is, in practice, a periodic bulk export. Any
// downstream training job can read the file in one line of code.
func (s *Store) DumpCSVGz(path string, cutoff time.Time) (int, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 0, fmt.Errorf("dump mkdir %s: %w", dir, err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("dump create: %w", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	w := csv.NewWriter(gz)
	defer w.Flush()

	if err := w.Write([]string{
		"ts", "client_id", "method", "path", "user_agent",
		"header_bitmap", "ja3", "ja4",
		"score", "signals_json", "decision", "features_json",
	}); err != nil {
		return 0, err
	}

	rows, err := s.db.Query(`SELECT ts, client_id, method, path, user_agent,
			header_bitmap, ja3, ja4, score, signals_json, decision, features_json
		FROM events WHERE ts < ? ORDER BY id`,
		cutoff.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var (
			ts, clientID, method, path, ua        string
			ja3, ja4, signalsJSON, decision, feat string
			headerBM                              int64
			score                                 int
		)
		if err := rows.Scan(&ts, &clientID, &method, &path, &ua,
			&headerBM, &ja3, &ja4, &score, &signalsJSON, &decision, &feat); err != nil {
			return count, err
		}
		if err := w.Write([]string{
			ts, clientID, method, path, ua,
			strconv.FormatInt(headerBM, 10), ja3, ja4,
			strconv.Itoa(score), signalsJSON, decision, feat,
		}); err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}
