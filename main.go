package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)



const (
	// Hardcoded deployment defaults
	defaultAPI   = "https://api.haveibeensshpwned.com:5000"
	defaultKC    = "https://auth.haveibeensshpwned.com:8443"
	defaultRealm = "haveibeensshpwned"
	defaultCID   = "habsp-cli" // PUBLIC client (no secret)
)

var (
    publicTypes = map[string]bool{
        "ssh-rsa": true, "ssh-dss": true, "ssh-ed25519": true,
        "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
        "sk-ecdsa-sha2-nistp256@openssh.com": true, "sk-ssh-ed25519@openssh.com": true,
    }
    privateMarkers = []string{
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "PuTTY-User-Key-File-",
		"openssh-key-v1",
    }
    b64Re       = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
    spaceRe     = regexp.MustCompile(`\s+`)
    httpTimeout = 30 * time.Second
)

// ---------- CLI config ----------
type cfg struct {
	api      string
	kc       string
	realm    string
	clientID string

	authFlow string // "device" or "password"
	user     string
	pass     string

	path     string // file OR folder
	insecure bool
	caPath   string
	offline  bool

	debug bool

	// convenience toggles to allow --device / --password
	useDevice   bool
	usePassword bool
}

func parseFlags() cfg {
	var c cfg
	// Hidden/embedded deploy defaults:
	c.api = defaultAPI
	c.kc = defaultKC
	c.realm = defaultRealm
	c.clientID = defaultCID

	// Visible knobs:
	flag.StringVar(&c.authFlow, "auth", "device", "Auth flow: device | password")
	flag.StringVar(&c.user, "user", "", "Username (email) [password flow]")
	flag.StringVar(&c.pass, "password", "", "Password [password flow]")
	flag.StringVar(&c.path, "path", "", "File or folder to scan")
	flag.BoolVar(&c.insecure, "insecure", false, "Disable TLS verification (NOT recommended)")
	flag.StringVar(&c.caPath, "ca", "", "Path to custom CA bundle (PEM)")
	flag.BoolVar(&c.offline, "offline", false, "Request offline_access (refresh token)")

	// convenience: --device / --password
	flag.BoolVar(&c.useDevice, "device", false, "Shortcut for --auth device")
	flag.BoolVar(&c.usePassword, "password-auth", false, "Shortcut for --auth password")
	
	flag.BoolVar(&c.debug, "debug", false, "Show server internals (pool/act/wait) in the HUD")

	flag.Parse()

	// Positional forms: first non-flag arg can be "device" or "password"
	args := flag.Args()
	if len(args) > 0 {
		switch strings.ToLower(args[0]) {
		case "device":
			c.authFlow = "device"
			// allow trailing path positional
			if c.path == "" && len(args) > 1 {
				c.path = args[len(args)-1]
			}
		case "password":
			c.authFlow = "password"
			if c.path == "" && len(args) > 1 {
				c.path = args[len(args)-1]
			}
		case "auth":
			if len(args) > 1 && (args[1] == "device" || args[1] == "password") {
				c.authFlow = args[1]
				if c.path == "" && len(args) > 2 {
					c.path = args[len(args)-1]
				}
			}
		default:
			// if it's not recognized, treat the last arg as path if not provided
			if c.path == "" {
				c.path = args[len(args)-1]
			}
		}
	}
	if c.useDevice {
		c.authFlow = "device"
	}
	if c.usePassword {
		c.authFlow = "password"
	}
	return c
}

// ---------- HTTP + TLS ----------
func makeHTTPClient(insecure bool, caPath string) (*http.Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if insecure {
		tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec
	}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA %s: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("failed to parse CA bundle")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Timeout: httpTimeout, Transport: tr}, nil
}

// ---------- Tokens ----------
type tokenSet struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

func (t *tokenSet) Expired() bool {
	return time.Now().After(t.Expiry.Add(-30 * time.Second))
}

type keycloak struct {
	base   string
	realm  string
	client string
	http   *http.Client
}

// PKCE helpers (for device flow w/ PKCE)
type pkcePair struct {
	Verifier  string
	Challenge string
	Method    string // "S256"
}

func genPKCE() (pkcePair, error) {
	// 32 random bytes -> base64url (43-128 chars recommended)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return pkcePair{}, err
	}
	ver := b64url(b)
	h := sha256.Sum256([]byte(ver))
	chal := b64url(h[:])
	return pkcePair{Verifier: ver, Challenge: chal, Method: "S256"}, nil
}

func b64url(b []byte) string {
	s := base64.RawURLEncoding.EncodeToString(b) // no padding
	return s
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func (kc *keycloak) passwordGrant(ctx context.Context, user, pass string, offline bool) (*tokenSet, error) {
	scope := "openid"
	if offline {
		scope += " offline_access"
	}
	body := fmt.Sprintf("grant_type=password&client_id=%s&username=%s&password=%s&scope=%s",
		urlEnc(kc.client), urlEnc(user), urlEnc(pass), urlEnc(scope))
	req, _ := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", strings.TrimRight(kc.base, "/"), kc.realm),
		strReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := kc.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return nil, fmt.Errorf("password grant failed (%d): %s", res.StatusCode, string(b))
	}
	var tr tokenResp
	if err := json.NewDecoder(res.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return &tokenSet{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}, nil
}

type deviceAuthResp struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func (kc *keycloak) deviceStart(ctx context.Context, pkce pkcePair, offline bool) (*deviceAuthResp, error) {
	scope := "openid"
	if offline {
		scope += " offline_access"
	}
	body := fmt.Sprintf("client_id=%s&scope=%s&code_challenge=%s&code_challenge_method=%s",
		urlEnc(kc.client), urlEnc(scope), urlEnc(pkce.Challenge), urlEnc(pkce.Method))
	req, _ := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth/device", strings.TrimRight(kc.base, "/"), kc.realm),
		strReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := kc.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("device auth start failed (%d): %s", res.StatusCode, string(b))
	}
	var dr deviceAuthResp
	if err := json.NewDecoder(res.Body).Decode(&dr); err != nil {
		return nil, err
	}
	if dr.Interval <= 0 {
		dr.Interval = 5
	}
	return &dr, nil
}

func (kc *keycloak) devicePoll(ctx context.Context, devCode, codeVerifier string) (*tokenSet, string, error) {
	body := fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s&client_id=%s&code_verifier=%s",
		urlEnc(devCode), urlEnc(kc.client), urlEnc(codeVerifier))
	req, _ := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", strings.TrimRight(kc.base, "/"), kc.realm),
		strReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := kc.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()

	if res.StatusCode == 400 {
		var e struct{ Error string `json:"error"` }
		_ = json.NewDecoder(res.Body).Decode(&e)
		// expected: authorization_pending, slow_down, expired_token, access_denied
		return nil, e.Error, nil
	}
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, "", fmt.Errorf("device poll failed (%d): %s", res.StatusCode, string(b))
	}
	var tr tokenResp
	if err := json.NewDecoder(res.Body).Decode(&tr); err != nil {
		return nil, "", err
	}
	return &tokenSet{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}, "", nil
}

func (kc *keycloak) refresh(ctx context.Context, refreshToken string) (*tokenSet, error) {
	body := fmt.Sprintf("grant_type=refresh_token&client_id=%s&refresh_token=%s",
		urlEnc(kc.client), urlEnc(refreshToken))
	req, _ := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", strings.TrimRight(kc.base, "/"), kc.realm),
		strReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := kc.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return nil, fmt.Errorf("refresh failed (%d): %s", res.StatusCode, string(b))
	}
	var tr tokenResp
	if err := json.NewDecoder(res.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return &tokenSet{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}, nil
}

// ---------- API client ----------
type apiClient struct {
	base   string
	token  *tokenSet
	kc     *keycloak
	client *http.Client
}

func (a *apiClient) authHeader() string { return "Bearer " + a.token.AccessToken }

func (a *apiClient) ensureToken(ctx context.Context) error {
	if a.token != nil && !a.token.Expired() {
		return nil
	}
	if a.token == nil || a.token.RefreshToken == "" {
		return errors.New("no token; re-auth required")
	}
	ts, err := a.kc.refresh(ctx, a.token.RefreshToken)
	if err != nil {
		return err
	}
	a.token = ts
	return nil
}

func (a *apiClient) getJSON(ctx context.Context, path string) (map[string]any, error) {
	if err := a.ensureToken(ctx); err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", a.base+path, nil)
	req.Header.Set("Authorization", a.authHeader())
	res, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == 401 {
		// one retry after refresh
		if err := a.ensureToken(ctx); err != nil {
			return nil, err
		}
		req2, _ := http.NewRequestWithContext(ctx, "GET", a.base+path, nil)
		req2.Header.Set("Authorization", a.authHeader())
		res2, err2 := a.client.Do(req2)
		if err2 != nil {
			return nil, err2
		}
		defer res2.Body.Close()
		res = res2
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("GET %s -> %d: %s", path, res.StatusCode, string(b))
	}
	var j map[string]any
	err = json.NewDecoder(res.Body).Decode(&j)
	return j, err
}

func (a *apiClient) postJSON(ctx context.Context, path string, payload any) (map[string]any, error) {
	if err := a.ensureToken(ctx); err != nil {
		return nil, err
	}
	enc, _ := json.Marshal(payload)

	newReq := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", a.base+path, bytes.NewReader(enc))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", a.authHeader())
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}

	req, _ := newReq()
	res, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == 401 {
		if err := a.ensureToken(ctx); err != nil {
			return nil, err
		}
		req2, _ := newReq()
		res2, err2 := a.client.Do(req2)
		if err2 != nil {
			return nil, err2
		}
		defer res2.Body.Close()
		res = res2
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("POST %s -> %d: %s", path, res.StatusCode, string(body))
	}
	var j map[string]any
	if ct := res.Header.Get("Content-Type"); strings.Contains(ct, "application/json") {
		if err := json.NewDecoder(res.Body).Decode(&j); err != nil {
			return nil, err
		}
	} else {
		j = map[string]any{}
	}
	return j, nil
}

// ---------- Scan (private/public) ----------
type privHitInfo struct{ file string; line int }

// --- Block regexes ---
var pemBlockRe = regexp.MustCompile(`(?ms)-----BEGIN [^-]+-----\s*.*?-----END [^-]+-----`)
var opensshLineRe = regexp.MustCompile(`(?m)^(?:ssh-(?:rsa|dss|ed25519)|ecdsa-[^\s]+|sk-[^\s]+)\s+[A-Za-z0-9+/=]+(?:\s+[^\r\n]+)?`)

type keyBlock struct {
    Text  string
    Start int // byte offset in the original file (for line calculation)
}

// Split into PEM blocks and OpenSSH one-liners, preserving order.
func splitKeyBlocksAll(s string) []keyBlock {
    out := []keyBlock{}

    // collect all matches with positions
    idxs := [][]int{}
    for _, m := range pemBlockRe.FindAllStringIndex(s, -1) {
        idxs = append(idxs, m)
    }
    for _, m := range opensshLineRe.FindAllStringIndex(s, -1) {
        idxs = append(idxs, m)
    }
    sort.Slice(idxs, func(i, j int) bool { return idxs[i][0] < idxs[j][0] })

    for _, m := range idxs {
        out = append(out, keyBlock{Text: strings.TrimSpace(s[m[0]:m[1]]), Start: m[0]})
    }
    return out
}

// Classify a block.
func classifyBlock(b string) (kind, reason string) {
    t := strings.TrimSpace(b)
    // obvious private markers
    for _, m := range privateMarkers {
        if strings.Contains(t, m) {
            return "private", "PEM/PPK private marker"
        }
    }
    // PEM public?
    if strings.HasPrefix(t, "-----BEGIN ") && strings.Contains(t, "PUBLIC KEY-----") {
        return "public", "PEM public"
    }
    // OpenSSH one-liner?
    if opensshLineRe.MatchString(t) {
        // sanity check Base64
        parts := strings.Fields(t)
        if len(parts) >= 2 && isValidB64(parts[1]) {
            if _, err := base64.StdEncoding.DecodeString(padB64(parts[1])); err == nil {
                return "public", "OpenSSH one-liner"
            }
        }
        return "unknown", "OpenSSH-like but invalid base64"
    }

    // headerless base64 that *decodes* to openssh-key-v1\0 → private
    compact := strings.ReplaceAll(t, " ", "")
    if len(compact) >= 128 && b64Re.MatchString(compact) {
        if raw, err := base64.StdEncoding.DecodeString(padB64(compact)); err == nil {
            if bytes.HasPrefix(raw, []byte("openssh-key-v1\x00")) || looksDERPrivate(raw) {
                return "private", "headerless private (openssh-key-v1/DER)"
            }
        }
    }
    return "unknown", "not SSH"
}

// Normalize/return OpenSSH one-liner from any block.
// - returns "" if not convertible/valid.
func extractOpenSSH(b string) string {
    t := strings.TrimSpace(b)

    // Case 1: already an OpenSSH one-liner
    if opensshLineRe.MatchString(t) {
        // squash spaces
        t = spaceRe.ReplaceAllString(t, " ")
        parts := strings.SplitN(t, " ", 3)
        if len(parts) >= 2 && isValidB64(parts[1]) {
            if _, err := base64.StdEncoding.DecodeString(padB64(parts[1])); err == nil {
                if len(parts) == 3 {
                    return parts[0] + " " + parts[1] + " " + parts[2]
                }
                return parts[0] + " " + parts[1]
            }
        }
        return ""
    }

    // Case 2: PEM public -> convert to OpenSSH
    if strings.HasPrefix(t, "-----BEGIN ") && strings.Contains(t, "PUBLIC KEY-----") {
        if s := pemPublicToOpenSSH(t); s != "" {
            return s
        }
        return ""
    }

    return ""
}

// Parse PEM public key and convert to OpenSSH authorized_keys.
func pemPublicToOpenSSH(pemText string) string {
    blk, _ := pem.Decode([]byte(pemText))
    if blk == nil {
        return ""
    }

    var pub any
    var err error

    switch blk.Type {
    case "RSA PUBLIC KEY":
        pub, err = x509.ParsePKCS1PublicKey(blk.Bytes)
    case "PUBLIC KEY", "EC PUBLIC KEY", "DSA PUBLIC KEY":
        pub, err = x509.ParsePKIXPublicKey(blk.Bytes)
    default:
        // Unknown or private types are handled by classifyBlock
        return ""
    }
    if err != nil || pub == nil {
        return ""
    }

    // Ensure type is supported by ssh.NewPublicKey
    switch pub.(type) {
    case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
        // ok
    default:
        return ""
    }

    pk, err := ssh.NewPublicKey(pub)
    if err != nil {
        return ""
    }
    return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

func scanPathProgress(p string) ([]string, *privHitInfo, error) {
    if p == "" { return nil, nil, errors.New("empty path") }
    info, err := os.Stat(p)
    if err != nil { return nil, nil, err }

    seen := map[string]bool{}
    out  := []string{}
    var priv *privHitInfo

    filesScanned := 0
    keysFound := 0
    lastUpd := time.Now()

    printScanHUD := func(cur string) {
        if time.Since(lastUpd) < 100*time.Millisecond { return }
        base := fmt.Sprintf("[scan] files:%d  keys:%d  ", filesScanned, keysFound)
        cols := termWidth()
        remain := cols - 1 - len(base)
        if remain < 0 { remain = 0 }
        if len(cur) > remain {
            if remain > 1 { cur = "…" + cur[len(cur)-(remain-1):] } else { cur = "" }
        }
        printHUDLine(base+cur, len(base)+len(cur))
        lastUpd = time.Now()
    }

    // scan a single file (block-based)
    scanFile := func(path string) error {
        b, err := os.ReadFile(path)
        if err != nil { return nil } // ignore unreadables
        s := string(b)

        blocks := splitKeyBlocksAll(s)
        for _, bl := range blocks {
            kind, _ := classifyBlock(bl.Text)
            switch kind {
            case "private":
                // compute 1-based line number at block start
                line := 1 + strings.Count(s[:bl.Start], "\n")
                priv = &privHitInfo{file: path, line: line}
                return errors.New("STOP_PRIV")
            case "public":
                if pub := extractOpenSSH(bl.Text); pub != "" {
                    typ, b64 := splitTypeAndB64(pub)
                    key := typ + " " + b64
                    if !seen[key] {
                        seen[key] = true
                        out = append(out, pub)
                        keysFound++
                    }
                }
            default:
                // ignore unknown junk
            }
        }
        return nil
    }

    stopPriv := errors.New("STOP_PRIV")

    if info.IsDir() {
        err = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
            if err != nil { return nil }
            if d.IsDir() {
                printScanHUD(path)
                return nil
            }
            filesScanned++
            printScanHUD(path)
            if e := scanFile(path); e != nil {
                if errors.Is(e, stopPriv) { return stopPriv }
                return nil
            }
            return nil
        })
        endProgressLine()
        if errors.Is(err, stopPriv) {
            return out, priv, nil
        }
        if err != nil { return nil, nil, err }
        return out, nil, nil
    }

    // single file
    filesScanned = 1
    printScanHUD(p)
    _ = scanFile(p)
    endProgressLine()
    return out, priv, nil
}



// func scanPathProgress(p string) ([]string, *privHitInfo, error) {
// 	if p == "" { return nil, nil, errors.New("empty path") }
// 	info, err := os.Stat(p)
// 	if err != nil { return nil, nil, err }

// 	seen := map[string]bool{}
// 	out := []string{}
// 	var priv *privHitInfo

// 	filesScanned := 0
// 	keysFound := 0
// 	lastUpd := time.Now()

// 	printScanHUD := func(cur string) {
// 		// throttle updates to ~10fps
// 		if time.Since(lastUpd) < 100*time.Millisecond { return }
// 		base := fmt.Sprintf("[scan] files:%d  keys:%d  ", filesScanned, keysFound)
// 		cols := termWidth()
// 		remain := cols - 1 - len(base) // keep 1 col spare
// 		if remain < 0 { remain = 0 }
// 		if len(cur) > remain {
// 			if remain > 1 {
// 				cur = "…" + cur[len(cur)-(remain-1):] // right-ellide
// 			} else {
// 				cur = ""
// 			}
// 		}
// 		printHUDLine(base+cur, len(base)+len(cur))
// 		lastUpd = time.Now()
// 	}

// 	scanFile := func(path string) error {
// 		fd, err := os.Open(path)
// 		if err != nil { return nil } // ignore unreadables
// 		defer fd.Close()

// 		sc := bufio.NewScanner(fd)
// 		ln := 0
// 		for sc.Scan() {
// 			ln++
// 			line := strings.TrimSpace(sc.Text())
// 			if line == "" || strings.HasPrefix(line, "#") {
// 				continue
// 			}
// 			if isPrivate(line) {
// 				priv = &privHitInfo{file: path, line: ln}
// 				return errors.New("STOP_PRIV")
// 			}
// 			if pub := extractPublic(line); pub != "" {
// 				typ, b64 := splitTypeAndB64(pub)
// 				key := typ + " " + b64
// 				if !seen[key] {
// 					seen[key] = true
// 					out = append(out, pub)
// 					keysFound++
// 				}
// 			}
// 		}
// 		return nil
// 	}

// 	if info.IsDir() {
// 		stopPriv := errors.New("STOP_PRIV")
// 		err = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
// 			if err != nil { return nil }
// 			if d.IsDir() {
// 				printScanHUD(path)
// 				return nil
// 			}
// 			filesScanned++
// 			printScanHUD(path)
// 			if e := scanFile(path); e != nil {
// 				if errors.Is(e, stopPriv) { return stopPriv }
// 				return nil
// 			}
// 			return nil
// 		})
// 		endProgressLine()
// 		if errors.Is(err, stopPriv) {
// 			return out, priv, nil
// 		}
// 		if err != nil { return nil, nil, err }
// 		return out, nil, nil
// 	}

// 	// Single file
// 	filesScanned = 1
// 	printScanHUD(p)
// 	_ = scanFile(p)
// 	endProgressLine()
// 	return out, priv, nil
// }




// func scanPath(p string) ([]string, *privHitInfo, error) {
// 	if p == "" {
// 		return nil, nil, errors.New("empty path")
// 	}
// 	info, err := os.Stat(p)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	var files []string
// 	if info.IsDir() {
// 		err = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
// 			if err != nil {
// 				return nil
// 			}
// 			if d.IsDir() {
// 				return nil
// 			}
// 			files = append(files, path)
// 			return nil
// 		})
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 	} else {
// 		files = []string{p}
// 	}

// 	seen := map[string]bool{}
// 	out := []string{}

// 	for _, f := range files {
// 		fd, err := os.Open(f)
// 		if err != nil {
// 			continue
// 		}
// 		sc := bufio.NewScanner(fd)
// 		ln := 0
// 		for sc.Scan() {
// 			ln++
// 			line := strings.TrimSpace(sc.Text())
// 			if line == "" || strings.HasPrefix(line, "#") {
// 				continue
// 			}

// 			if isPrivate(line) {
// 				fd.Close()
// 				return out, &privHitInfo{file: f, line: ln}, nil
// 			}
// 			if pub := extractPublic(line); pub != "" {
// 				typ, b64 := splitTypeAndB64(pub)
// 				key := typ + " " + b64
// 				if !seen[key] {
// 					seen[key] = true
// 					out = append(out, pub)
// 				}
// 			}
// 		}
// 		fd.Close()
// 	}
// 	return out, nil, nil
// }

func isPrivate(s string) bool {
    txt := strings.TrimSpace(s)
    for _, m := range privateMarkers {
        if strings.Contains(txt, m) {
            return true
        }
    }
    // Headerless base64 heuristic
    t := strings.ReplaceAll(txt, " ", "")
    if len(t) >= 64 && b64Re.MatchString(t) {
        raw, err := base64.StdEncoding.DecodeString(padB64(t))
        if err == nil && (bytes.HasPrefix(raw, []byte("openssh-key-v1\x00")) || looksDERPrivate(raw)) {
            return true
        }
    }
    return false
}


func looksDERPrivate(raw []byte) bool {
	if len(raw) == 0 || raw[0] != 0x30 {
		return false
	}
	n := min(16, len(raw))
	for i := 2; i < n; i++ {
		if raw[i] == 0x02 {
			return true
		}
	}
	return false
}

func extractPublic(line string) string {
	line = spaceRe.ReplaceAllString(line, " ")
	parts := strings.Split(line, " ")
	// find first known type
	keyIdx := -1
	for i, p := range parts {
		if publicTypes[p] || strings.HasSuffix(p, "-cert-v01@openssh.com") {
			keyIdx = i
			break
		}
	}
	if keyIdx == -1 || keyIdx+1 >= len(parts) {
		return ""
	}
	typ := parts[keyIdx]
	b64 := parts[keyIdx+1]
	if !isValidB64(b64) {
		return ""
	}
	if _, err := base64.StdEncoding.DecodeString(padB64(b64)); err != nil {
		return ""
	}
	comment := ""
	if keyIdx+2 < len(parts) {
		comment = strings.Join(parts[keyIdx+2:], " ")
	}
	if comment != "" {
		return fmt.Sprintf("%s %s %s", typ, b64, comment)
	}
	return fmt.Sprintf("%s %s", typ, b64)
}

func splitTypeAndB64(pub string) (string, string) {
	parts := strings.Split(pub, " ")
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return pub, ""
}

func isValidB64(s string) bool { return b64Re.MatchString(s) }
func padB64(s string) string {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}
func min(a, b int) int { if a < b { return a }; return b }
func maxInt(a, b int) int { if a > b { return a }; return b }

// ---------- Rate + upload ----------
func uploadWithRate(ctx context.Context, api *apiClient, keys []string, clientID string, showDebug bool) error {
    
	const (
        hbEvery    = 5 * time.Second
        reqTimeout = 10 * time.Second
        maxRetries = 5
        sleepOn503 = 3 * time.Second
        alpha      = 0.25 // EMA smoothing for measured throughput
    )
	
	total := len(keys)
    if total == 0 {
        fmt.Println("[upload] nothing to upload")
		if showDebug {
    		fmt.Printf("[debug] POST %s/api/rate/lease  (timeout=%s)\n", api.base, reqTimeout)
		}
        return nil
    }

    sent := 0
    grantedRate := 0
    lastHB := time.Time{}
    retries := 0

    // EMA of actually-enqueued keys/sec
    var ema float64
    lastSent := 0
    lastTick := time.Now()

    // throttled status (only if --debug)
    lastStatus := time.Time{}
    debug := (*debugStats)(nil)

	// --- token bucket (local) ---
	tokens := 0.0            // current token balance
	refillRate := 0.0        // tokens/sec (== grantedRate)
	lastRefill := time.Now() // last refill instant
	const maxBurstSec = 1.5   // allow up to 1.5s worth of burst


    // tight-timeout callers …
    callWithTO := func(path string, payload any) (map[string]any, error) {
        ctx2, cancel := context.WithTimeout(ctx, reqTimeout)
        defer cancel()
        return api.postJSON(ctx2, path, payload)
    }
    requestLease := func(rem int) (map[string]any, error) {
        return callWithTO("/api/rate/lease", map[string]any{
            "client_id": clientID,
            "estimate_total": total,
            "estimate_remaining": rem,
        })
    }
    heartbeat := func(rem int) (map[string]any, error) {
        return callWithTO("/api/rate/heartbeat", map[string]any{
            "client_id": clientID,
            "estimate_remaining": rem,
        })
    }

    fmt.Printf("[3/3] Uploading %d key(s)…\n", total)

    for sent < total {
        select {
        case <-ctx.Done():
            endProgressLine()
            return ctx.Err()
        default:
        }

		loopStart := time.Now()

		// Refill by wall time since lastRefill
		dtRefill := loopStart.Sub(lastRefill).Seconds()
		if dtRefill > 0 {
			tokens += refillRate * dtRefill
			cap := refillRate * maxBurstSec
			if tokens > cap {
				tokens = cap
			}
			lastRefill = loopStart
		}

        now := time.Now()
        // refresh lease / heartbeat
        var st map[string]any
        var err error

        if grantedRate == 0 || now.Sub(lastHB) >= hbEvery {
            if grantedRate == 0 {
                st, err = requestLease(total - sent)
            } else {
                st, err = heartbeat(total - sent)
            }
            if err != nil {
                retries++
                if retries > maxRetries {
                    endProgressLine()
                    return fmt.Errorf("rate service unreachable after %d retries: %w", maxRetries, err)
                }
                endProgressLine()
                fmt.Printf("[warn] %v (retry %d/%d)\n", err, retries, maxRetries)
                time.Sleep(sleepOn503)
                grantedRate = 0
                continue
            }
            retries = 0
            lastHB = now
        }

        state := getStr(st, "state")
        pool := getInt(st, "pool_per_sec")

		gotGrant := false
		if state == "active" {
			if v, ok := getIntOK(st, "uploads_per_second"); ok && v > 0 {
				grantedRate = v
				gotGrant = true
			}
		}
		if gotGrant {
			refillRate = float64(grantedRate)
			cap := refillRate * maxBurstSec
			if tokens > cap {
				tokens = cap
			}
		}

        //Debug internals (throttled)
        if showDebug && time.Since(lastStatus) >= 2*time.Second {
            if rs, err := api.getRateStatus(ctx, clientID); err == nil {
                debug = &debugStats{
                    pool:   func() int { if pool > 0 { return pool }; return rs.PoolPerSec }(),
                    active: rs.ActiveClients,
                    waiting: rs.WaitingClients,
                }
                if state == "" && rs.You.State != "" { state = rs.You.State }
                if pool == 0 && rs.PoolPerSec > 0 { pool = rs.PoolPerSec }
            }
            lastStatus = time.Now()
        } else if !showDebug {
            debug = nil
        }

        // WAITING view
        if state == "waiting" {
            eta := getInt(st, "eta_seconds")
            drawProgress(sent, total, ema, grantedRate, "waiting", eta, debug)
            // snooze gently (bounded)
            sleep := time.Duration(maxInt(2, eta/6)) * time.Second
            if sleep > 10*time.Second { sleep = 10 * time.Second }
            time.Sleep(sleep)
            grantedRate = 0
			tokens = 0
            continue
        }

        // ACTIVE: grant & enqueue a ~1s batch
		if !gotGrant {
			if grantedRate <= 0 {
				drawProgress(sent, total, ema, grantedRate, "active", 0, debug)
				time.Sleep(500 * time.Millisecond)
				continue
			}
		}

		// Decide how many we can send this tick (tokens + grant + remaining)
		want := minInt(int(tokens), total-sent)
		if grantedRate > 0 && want > grantedRate {
			want = grantedRate
		}

		if want <= 0 {
			// not enough budget yet — let tokens accumulate a bit
			drawProgress(sent, total, ema, grantedRate, "active", 0, debug)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		batch := want
		batchKeys := keys[sent : sent+batch]

        if _, err := callWithTO("/api/keys/enqueue", map[string]any{"mode":"cli", "keys": batchKeys}); err != nil {
            retries++
            if retries > maxRetries {
                endProgressLine()
                return fmt.Errorf("enqueue failed after %d retries: %w", maxRetries, err)
            }
            endProgressLine()
            fmt.Printf("[warn] enqueue: %v (retry %d/%d)\n", err, retries, maxRetries)
            time.Sleep(sleepOn503)
            grantedRate = 0
            continue
        }
        retries = 0

        sent += batch

		tokens -= float64(batch)
		if tokens < 0 {
			tokens = 0
		}

        // update measured rate (EMA)
        dt := time.Since(lastTick).Seconds()
        if dt > 0 {
            inst := float64(sent-lastSent) / dt
            if ema == 0 {
                ema = inst
            } else {
                ema = alpha*inst + (1-alpha)*ema
            }
            lastTick = time.Now()
            lastSent = sent
        }

        remaining := total - sent
        eta := 0
        if ema > 0 {
            eta = int(float64(remaining)/ema + 0.5)
        }

        drawProgress(sent, total, ema, grantedRate, "active", eta, debug)

		// ✅ pace the entire loop, not just enqueue time
		loopDur := time.Since(loopStart)
		if loopDur < time.Second {
			select {
			case <-ctx.Done():
				endProgressLine()
				return ctx.Err()
			case <-time.After(time.Second - loopDur):
			}
		}

    }

    endProgressLine()

	// show a final 100% bar and keep it on screen
	drawProgress(total, total, ema, grantedRate, "done", 0, nil)
	finishProgressLine()

    fmt.Println("[done] Upload complete.")
    return nil
}



// ---------- helpers ----------
var lastCells int

func getenv(k, def string) string {
    if v := os.Getenv(k); v != "" { return v }
    return def
}

func getIntOK(m map[string]any, k string) (int, bool) {
    v, ok := m[k]
    if !ok { return 0, false }
    switch x := v.(type) {
    case float64: return int(x), true
    case int:     return x, true
    default:      return 0, false
    }
}

func termWidth() int {
    w, _, err := term.GetSize(int(os.Stdout.Fd()))
    if err != nil || w < 40 {
        return 80
    }
    return w
}

func printHUDLine(s string, cells int) {
    if lastCells > cells {
        // overwrite any leftover characters from the previous, longer line
        s = s + strings.Repeat(" ", lastCells-cells)
    }
    fmt.Printf("\r%s", s)
    lastCells = cells
}

func endProgressLine() {
    if lastCells > 0 {
        fmt.Printf("\r%s\r\n", strings.Repeat(" ", lastCells))
        lastCells = 0
    } else {
        fmt.Println()
    }
}

func finishProgressLine() {
    fmt.Print("\n")
    lastCells = 0
}


func getStr(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
func getInt(m map[string]any, k string) int {
	if v, ok := m[k]; ok {
		switch x := v.(type) {
		case float64:
			return int(x)
		case int:
			return x
		}
	}
	return 0
}

func urlEnc(s string) string {
	r := strings.NewReplacer("%", "%25", "&", "%26", "+", "%2B", " ", "%20")
	return r.Replace(s)
}
func strReader(s string) io.Reader { return strings.NewReader(s) }

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		// Using rundll32 avoids quoting weirdness with "start"
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default: // linux, bsd, etc.
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func pretty(sec int) string {
	if sec <= 0 { return "0s" }
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// ASCII bar to avoid Unicode width issues.
// Keep this single definition (delete any other drawProgress / debugStats you still have)
type debugStats struct {
    pool, active, waiting int
}

func drawProgress(sent, total int, rateEMA float64, granted int, state string, etaSec int, dbg *debugStats) {
    if total <= 0 { total = 1 }
    pct := float64(sent) / float64(total)

    base := fmt.Sprintf(" %3d%%  %d/%d  eff:%d/s  grant:%d/s  %-7s ETA:%s",
        int(pct*100+0.5), sent, total, int(rateEMA+0.5), granted, state, pretty(etaSec))
    if dbg != nil {
        base += fmt.Sprintf("  pool:%d/s  act:%d wait:%d", dbg.pool, dbg.active, dbg.waiting)
    }

    cols := termWidth()
    // 1 spare col so we don’t wrap at the edge: cols - 1
    barW := cols - 1 - 2 - len(base) // 2 for the [ ]
    if barW < 10 { barW = 10 }

    fill := int(pct * float64(barW))
    if fill > barW { fill = barW }
    bar := strings.Repeat("█", fill) + strings.Repeat("░", barW-fill)

    line := "[" + bar + "]" + base
    // base is ASCII-only; barW is in terminal cells
    cells := 2 + barW + len(base)

    printHUDLine(line, cells)
}



func minInt(a, b int) int { if a < b { return a }; return b }

// --- API: rate status --------------------------------------------------------

type rateStatus struct {
	PoolPerSec     int `json:"pool_per_sec"`
	ActiveClients  int `json:"active_clients"`
	WaitingClients int `json:"waiting_clients"`
	You            struct {
		State             string `json:"state"`
		UploadsPerSecond  int    `json:"uploads_per_second"`
		Position          int    `json:"position"`
		EtaSeconds        int    `json:"eta_seconds"`
		ValidUntil        int64  `json:"valid_until"`
	} `json:"you"`
}

func (a *apiClient) getRateStatus(ctx context.Context, clientID string) (*rateStatus, error) {
	if err := a.ensureToken(ctx); err != nil { return nil, err }
	req, _ := http.NewRequestWithContext(ctx, "GET", a.base+"/api/rate/status?client_id="+clientID, nil)
	req.Header.Set("Authorization", a.authHeader())
	res, err := a.client.Do(req)
	if err != nil { return nil, err }
	defer res.Body.Close()
	if res.StatusCode == 503 { // Redis/rate svc unavailable
		return nil, errors.New("rate service unavailable")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return nil, fmt.Errorf("status %d: %s", res.StatusCode, string(body))
	}


	var rs rateStatus
	if err := json.NewDecoder(res.Body).Decode(&rs); err != nil { return nil, err }
	return &rs, nil
}


// ---------- main ----------
func main() {
	c := parseFlags()

	c.api   = getenv("HABSP_API",   defaultAPI)
	c.kc    = getenv("HABSP_KC",    defaultKC)
	c.realm = getenv("HABSP_REALM", defaultRealm)

	flag.StringVar(&c.api,   "api",   c.api,   "API base URL (env HABSP_API)")
	flag.StringVar(&c.kc,    "kc",    c.kc,    "Keycloak base URL (env HABSP_KC)")
	flag.StringVar(&c.realm, "realm", c.realm, "Keycloak realm (env HABSP_REALM)")

	if c.path == "" {
		// allow last positional as path if not set via --path
		args := flag.Args()
		if len(args) > 0 {
			c.path = args[len(args)-1]
		}
	}
	if c.path == "" {
		fmt.Fprintln(os.Stderr, "Usage: habsp-cli [device|password] --path <file-or-folder> [--offline] [--insecure] [--ca /path/to/ca.pem]")
		os.Exit(2)
	}

	hc, err := makeHTTPClient(c.insecure, c.caPath)
	if err != nil {
		fail(err)
	}

	kc := &keycloak{base: c.kc, realm: c.realm, client: c.clientID, http: hc}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Authenticate
	var ts *tokenSet
	switch strings.ToLower(c.authFlow) {
	case "password":
		if c.user == "" {
			fmt.Print("Username (email): ")
			fmt.Scanln(&c.user)
		}
		if c.pass == "" {
			fmt.Print("Password: ")
			pw, _ := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			c.pass = string(pw)
		}
		fmt.Println("[auth] password grant…")
		ts, err = kc.passwordGrant(ctx, c.user, c.pass, c.offline)
		if err != nil {
			fail(err)
		}
	default:
    fmt.Println("[auth] device flow (PKCE)…")

    pk, err := genPKCE()
    if err != nil { fail(err) }

    // deviceStart must include PKCE (code_challenge + code_challenge_method=S256)
    dr, err := kc.deviceStart(ctx, pk, c.offline)
    if err != nil { fail(err) }

    openURL := dr.VerificationURIComplete
    if openURL == "" {
        openURL = fmt.Sprintf("%s?user_code=%s",
            strings.TrimRight(dr.VerificationURI, "/"),
            urlEnc(dr.UserCode),
        )
    }
    fmt.Printf("Open: %s\n\n", openURL)
    openBrowser(openURL)

    deadline := time.Now().Add(time.Duration(dr.ExpiresIn) * time.Second)
    interval := time.Duration(dr.Interval) * time.Second
    if interval <= 0 { interval = 5 * time.Second }

    for {
        if time.Now().After(deadline) {
            fail(errors.New("device code expired; restart authentication"))
        }
        select {
        case <-ctx.Done():
            fail(ctx.Err())
        case <-time.After(interval):
        }

        // DO NOT redeclare 'ts' here; use a temp variable.
        tkn, errStr, err := kc.devicePoll(ctx, dr.DeviceCode, pk.Verifier)
        if err != nil { fail(err) }

        if errStr == "" {
            // success – promote temp into outer ts
            ts = tkn
            break
        }
        switch errStr {
        case "authorization_pending":
            // keep waiting
        case "slow_down":
            interval += 5 * time.Second
        case "access_denied":
            fail(errors.New("authorization denied in browser"))
        case "expired_token":
            fail(errors.New("device code expired; restart authentication"))
        default:
            fail(fmt.Errorf("device flow error: %s", errStr))
        }
    }
}

	api := &apiClient{
		base:   strings.TrimRight(c.api, "/"),
		token:  ts,
		kc:     kc,
		client: hc,
	}
	fmt.Println("[1/3] Authentication: OK")

	// 1) Scan path
	fmt.Println("[2/3] Scanning path for SSH public keys (and checking for private keys)…")
	keys, priv, err := scanPathProgress(c.path)
	if err != nil {
		fail(err)
	}
	if priv != nil {
		fmt.Printf("[error] PRIVATE KEY detected at %s:%d — aborting.\n", priv.file, priv.line)
		os.Exit(1)
	}
	if len(keys) == 0 {
		fmt.Println("[scan] no public keys found.")
		return
	}
	fmt.Printf("[scan] No private keys detected, continuing. Found %d public key(s). Starting upload…\n", len(keys))

	// 2) Upload with rate
	clientID := strings.ToLower(randomHex8())
	// main():
	if err := uploadWithRate(ctx, api, keys, clientID, c.debug); err != nil {
		fail(err)
	}
		fmt.Println("[done] All keys enqueued. It may take some time before they appear in the UI. Please be patient — the keys are being analyzed.")
	}

func randomHex8() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}
