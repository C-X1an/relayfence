package relayfence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const MaxAuditBytes = 16 << 20

type Event struct {
	Seq         uint64 `json:"seq"`
	At          string `json:"at"`
	Kind        string `json:"kind"`
	Session     uint64 `json:"session,omitempty"`
	Identity    string `json:"identity,omitempty"`
	Destination string `json:"destination,omitempty"`
	IP          string `json:"ip,omitempty"`
	Revision    uint64 `json:"revision,omitempty"`
	Bytes       uint64 `json:"bytes,omitempty"`
	Reason      string `json:"reason,omitempty"`
}
type Envelope struct {
	Event Event  `json:"event"`
	Prev  string `json:"prev"`
	Hash  string `json:"hash"`
}
type Audit interface{ Record(Event) error }
type FileAudit struct {
	mu       sync.Mutex
	file     *os.File
	previous string
	seq      uint64
	size     int64
	failed   bool
}

func eventHash(previous string, event Event) (string, error) {
	data, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(previous+"\n"), data...))
	return hex.EncodeToString(sum[:]), nil
}
func validKind(kind string) bool {
	return kind == "allowed" || kind == "denied" || kind == "closed" || kind == "policy"
}
func VerifyAudit(data []byte) ([]Envelope, error) {
	if len(data) > MaxAuditBytes || (len(data) > 0 && data[len(data)-1] != '\n') {
		return nil, errors.New("audit size/truncation")
	}
	previous := strings.Repeat("0", 64)
	var seq uint64
	out := []Envelope{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), MaxPolicyBytes)
	for scanner.Scan() {
		var row Envelope
		if err := StrictJSON(scanner.Bytes(), &row); err != nil {
			return nil, err
		}
		hash, err := eventHash(row.Prev, row.Event)
		if err != nil || row.Prev != previous || row.Hash != hash || row.Event.Seq != seq+1 || !validKind(row.Event.Kind) {
			return nil, errors.New("audit integrity failure")
		}
		if _, err := time.Parse(time.RFC3339Nano, row.Event.At); err != nil {
			return nil, errors.New("audit timestamp invalid")
		}
		previous = row.Hash
		seq = row.Event.Seq
		out = append(out, row)
	}
	return out, scanner.Err()
}
func ReadAudit(path string) ([]Envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxAuditBytes+1))
	if err != nil {
		return nil, err
	}
	return VerifyAudit(data)
}
func OpenAudit(path string) (*FileAudit, error) {
	if st, err := os.Lstat(path); err == nil {
		if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
			return nil, errors.New("audit must be a0600 regular file")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxAuditBytes+1))
	if err != nil {
		f.Close()
		return nil, err
	}
	rows, err := VerifyAudit(data)
	if err != nil {
		f.Close()
		return nil, err
	}
	a := &FileAudit{file: f, previous: strings.Repeat("0", 64), size: int64(len(data))}
	if len(rows) > 0 {
		a.previous = rows[len(rows)-1].Hash
		a.seq = rows[len(rows)-1].Event.Seq
	}
	return a, nil
}
func (a *FileAudit) Record(event Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed || a.file == nil || !validKind(event.Kind) {
		return ErrUnavailable
	}
	event.Seq = a.seq + 1
	event.At = time.Now().UTC().Format(time.RFC3339Nano)
	hash, err := eventHash(a.previous, event)
	if err != nil {
		return err
	}
	data, err := json.Marshal(Envelope{event, a.previous, hash})
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if a.size+int64(len(data)) > MaxAuditBytes {
		a.failed = true
		return ErrUnavailable
	}
	n, err := a.file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = a.file.Sync()
	}
	if err != nil {
		a.failed = true
		return err
	}
	a.size += int64(n)
	a.seq = event.Seq
	a.previous = hash
	return nil
}
func (a *FileAudit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	err := a.file.Close()
	a.file = nil
	return err
}

const inspectionTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>RelayFence audit inspection</title>
<style>body{font:16px system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;line-height:1.5}table{border-collapse:collapse;width:100%}th,td{border:1px solid #aaa;padding:.6rem;text-align:left;overflow-wrap:anywhere}caption{text-align:left;font-weight:bold;padding:1rem 0}small{display:block}code{overflow-wrap:anywhere}</style></head>
<body><h1>RelayFence</h1><p>Actual local audit records. Hash-chain integrity checked. This is not an independent attestation or a production-security claim.</p>
<table><caption>Execution evidence</caption><thead><tr><th scope="col">Sequence / time</th><th scope="col">Decision</th><th scope="col">Workload</th><th scope="col">Destination / IP</th><th scope="col">Revision / bytes</th><th scope="col">Reason</th></tr></thead><tbody>
{{range .}}<tr><td>{{.Event.Seq}}<small>{{.Event.At}}</small></td><td>{{.Event.Kind}}</td><td>{{.Event.Identity}}</td><td>{{.Event.Destination}}<small>{{.Event.IP}}</small></td><td>{{.Event.Revision}} / {{.Event.Bytes}}</td><td>{{.Event.Reason}}</td></tr>{{end}}</tbody></table>
<p>Opaque CONNECT payloads are not recorded. Proxy behavior is distinct from host-level direct-egress containment.</p></body></html>`

func InspectAudit(path string, out io.Writer) error {
	rows, err := ReadAudit(path)
	if err != nil {
		return err
	}
	tpl, err := template.New("audit").Parse(inspectionTemplate)
	if err != nil {
		return err
	}
	if err = tpl.Execute(out, rows); err != nil {
		return fmt.Errorf("render audit: %w", err)
	}
	return nil
}
