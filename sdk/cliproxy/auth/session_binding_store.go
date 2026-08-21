package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SessionBindingRecord is one persisted logical session-to-auth binding.
type SessionBindingRecord struct {
	AuthID    string    `json:"auth_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Aliases   []string  `json:"aliases"`
}

// SessionBindingStore persists session affinity independently from credentials.
type SessionBindingStore interface {
	Load(context.Context) ([]SessionBindingRecord, error)
	Save(context.Context, []SessionBindingRecord) error
}

type sessionBindingFile struct {
	Version   int                    `json:"version"`
	UpdatedAt time.Time              `json:"updated_at"`
	Bindings  []SessionBindingRecord `json:"bindings"`
}

// FileSessionBindingStore atomically stores bindings in one private JSON file.
type FileSessionBindingStore struct {
	mu   sync.Mutex
	path string
}

func NewFileSessionBindingStore(path string) *FileSessionBindingStore {
	return &FileSessionBindingStore{path: strings.TrimSpace(path)}
}

func (s *FileSessionBindingStore) Load(ctx context.Context) ([]SessionBindingRecord, error) {
	if s == nil || s.path == "" {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read session binding store: %w", err)
	}
	var envelope sessionBindingFile
	if err = json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("parse session binding store: %w", err)
	}
	if envelope.Version != 1 {
		return nil, fmt.Errorf("unsupported session binding store version %d", envelope.Version)
	}
	return envelope.Bindings, nil
}

func (s *FileSessionBindingStore) Save(ctx context.Context, records []SessionBindingRecord) error {
	if s == nil || s.path == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	sort.Slice(records, func(i, j int) bool {
		left, right := "", ""
		if len(records[i].Aliases) > 0 {
			left = records[i].Aliases[0]
		}
		if len(records[j].Aliases) > 0 {
			right = records[j].Aliases[0]
		}
		return left < right
	})
	envelope := sessionBindingFile{Version: 1, UpdatedAt: time.Now().UTC(), Bindings: records}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session binding store: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create session binding directory: %w", err)
	}
	tmpFile, err := os.CreateTemp(dir, filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create session binding temp file: %w", err)
	}
	tmp := tmpFile.Name()
	if err = tmpFile.Chmod(0o600); err == nil {
		_, err = tmpFile.Write(data)
	}
	if err == nil {
		err = tmpFile.Sync()
	}
	if closeErr := tmpFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write session binding store: %w", err)
	}
	if err = os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace session binding store: %w", err)
	}
	return syncSessionBindingDirectory(dir)
}

func syncSessionBindingDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open session binding directory: %w", err)
	}
	defer handle.Close()
	if err = handle.Sync(); err != nil {
		return fmt.Errorf("sync session binding directory: %w", err)
	}
	return nil
}
