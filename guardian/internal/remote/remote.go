package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"guardian/internal/config"
	"guardian/internal/dnsproxy"
	"guardian/internal/events"
)

const (
	defaultInterval = 5 * time.Minute
	maxConfigBytes  = 1 << 20
)

type Poller struct {
	Store         *config.Store
	Proxy         *dnsproxy.Proxy
	ConfigPath    string
	TokenPath     string
	PublicKeyPath string
	Interval      time.Duration
	APIBase       string
	Client        *http.Client
	Emit          func(events.Event)
	etag          string
}

func NewPoller(store *config.Store, proxy *dnsproxy.Proxy, configPath, dataDir string, emit func(events.Event)) (*Poller, error) {
	if store == nil || proxy == nil {
		return nil, errors.New("remote config requires a store and DNS proxy")
	}
	if configPath == "" || dataDir == "" {
		return nil, errors.New("remote config paths must not be empty")
	}
	return &Poller{
		Store:         store,
		Proxy:         proxy,
		ConfigPath:    configPath,
		TokenPath:     filepath.Join(dataDir, "github-token.txt"),
		PublicKeyPath: filepath.Join(dataDir, "config-public.key"),
		Interval:      defaultInterval,
		APIBase:       "https://api.github.com",
		Client:        &http.Client{Timeout: 20 * time.Second},
		Emit:          emit,
	}, nil
}

func (p *Poller) Run(ctx context.Context) error {
	interval := p.Interval
	if interval <= 0 {
		return errors.New("remote polling interval must be positive")
	}
	_ = p.PollOnce(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = p.PollOnce(ctx)
		}
	}
}

func (p *Poller) PollOnce(ctx context.Context) error {
	if p == nil || p.Store == nil || p.Proxy == nil || p.Client == nil {
		return errors.New("remote poller dependencies are incomplete")
	}
	current := p.Store.Get()
	if current == nil || current.Remote == nil || !current.Remote.Enabled {
		return nil
	}
	token, err := readToken(p.TokenPath)
	if err != nil {
		return p.failRemote(err)
	}
	body, etag, notModified, err := p.fetch(ctx, token, *current.Remote, p.etag)
	if err != nil {
		return p.failRemote(err)
	}
	if notModified {
		p.etag = etag
		p.report(events.Event{Type: "remote-sync", Message: "success: unchanged"})
		return nil
	}

	candidate, err := config.Parse(body)
	if err != nil {
		return p.reject(errors.New("remote config failed strict validation"))
	}
	if current.Version >= candidate.Version {
		if current.Version == candidate.Version && identicalConfig(current, candidate) {
			p.etag = etag
			p.report(events.Event{Type: "remote-sync", Message: "success: unchanged"})
			return nil
		}
		return p.reject(fmt.Errorf("config version %d must be greater than active version %d", candidate.Version, current.Version))
	}
	if current.Remote.RequireSignature {
		if err := verifySignature(body, p.PublicKeyPath, ctx, p.Client, token, *current.Remote, p.APIBase); err != nil {
			return p.reject(fmt.Errorf("config signature rejected: %w", err))
		}
	}
	commit := func() error {
		return persistConfig(p.ConfigPath, p.ConfigPath+".last-good.json", candidate)
	}
	if err := p.Proxy.ApplyConfig(candidate, commit); err != nil {
		return p.failRemote(fmt.Errorf("apply remote config: %w", err))
	}
	p.etag = etag
	p.report(events.Event{Type: "config-applied", Message: fmt.Sprintf("version=%d", candidate.Version)})
	p.report(events.Event{Type: "remote-sync", Message: fmt.Sprintf("applied version %d", candidate.Version)})
	return nil
}

func (p *Poller) reject(err error) error {
	p.report(events.Event{Type: "config-rejected", Message: err.Error()})
	p.report(events.Event{Type: "remote-sync-failed", Message: err.Error()})
	p.report(events.Event{Type: "remote-sync", Message: "failed: " + err.Error()})
	return err
}

func (p *Poller) failRemote(err error) error {
	p.report(events.Event{Type: "remote-sync-failed", Message: err.Error()})
	p.report(events.Event{Type: "remote-sync", Message: "failed: " + err.Error()})
	return err
}

func (p *Poller) report(event events.Event) {
	if p.Emit != nil {
		p.Emit(event)
	}
}

func (p *Poller) fetch(ctx context.Context, token string, source config.RemoteSource, etag string) ([]byte, string, bool, error) {
	endpoint, err := p.endpoint(source, source.Path)
	if err != nil {
		return nil, "", false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", false, err
	}
	setHeaders(request, token)
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := p.Client.Do(request)
	if err != nil {
		return nil, "", false, fmt.Errorf("fetch config: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return nil, response.Header.Get("ETag"), true, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("fetch config: GitHub returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxConfigBytes+1))
	if err != nil {
		return nil, "", false, fmt.Errorf("read config response: %w", err)
	}
	if len(body) > maxConfigBytes {
		return nil, "", false, errors.New("config response exceeds 1 MiB")
	}
	return body, response.Header.Get("ETag"), false, nil
}

func (p *Poller) endpoint(source config.RemoteSource, path string) (string, error) {
	base, err := url.Parse(p.APIBase)
	if err != nil || base.Scheme != "https" && base.Scheme != "http" || base.Host == "" {
		return "", errors.New("invalid GitHub API base URL")
	}
	segments := strings.Split(path, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/repos/" +
		url.PathEscape(source.Owner) + "/" + url.PathEscape(source.Repository) +
		"/contents/" + strings.Join(segments, "/")
	query := base.Query()
	query.Set("ref", source.Branch)
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func setHeaders(request *http.Request, token string) {
	request.Header.Set("Accept", "application/vnd.github.raw+json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("User-Agent", "Guardian-DNS-Filter")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

func readToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read protected GitHub token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("GitHub token file is empty or malformed")
	}
	for _, ch := range token {
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') &&
			(ch < '0' || ch > '9') && ch != '_' && ch != '-' {
			return "", errors.New("GitHub token file contains invalid characters")
		}
	}
	return token, nil
}

func identicalConfig(a, b *config.Config) bool {
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return sha256.Sum256(left) == sha256.Sum256(right)
}

func verifySignature(body []byte, publicKeyPath string, ctx context.Context, client *http.Client, token string, source config.RemoteSource, apiBase string) error {
	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("read config verification public key: %w", err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("public key file must contain a base64 Ed25519 public key")
	}
	helper := Poller{APIBase: apiBase}
	signatureURL, err := helper.endpoint(source, source.Path+".sig")
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, signatureURL, nil)
	if err != nil {
		return err
	}
	setHeaders(request, token)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("fetch config signature: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch config signature: GitHub returned HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil {
		return fmt.Errorf("read config signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("signature file must contain a base64 Ed25519 signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), body, signature) {
		return errors.New("Ed25519 verification failed")
	}
	return nil
}

func persistConfig(primaryPath, backupPath string, candidate *config.Config) error {
	oldBackup, backupErr := os.ReadFile(backupPath)
	hadBackup := backupErr == nil
	if backupErr != nil && !errors.Is(backupErr, os.ErrNotExist) {
		return fmt.Errorf("read previous last-known-good config: %w", backupErr)
	}
	if err := config.SaveLastKnownGood(backupPath, candidate); err != nil {
		return fmt.Errorf("save new last-known-good config: %w", err)
	}
	if err := config.SaveLastKnownGood(primaryPath, candidate); err != nil {
		if restoreErr := restoreFile(backupPath, oldBackup, hadBackup); restoreErr != nil {
			return errors.Join(fmt.Errorf("save main config: %w", err), fmt.Errorf("restore previous last-known-good: %w", restoreErr))
		}
		return fmt.Errorf("save main config: %w", err)
	}
	return nil
}

func restoreFile(path string, contents []byte, existed bool) error {
	if !existed {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".guardian-config-rollback-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
