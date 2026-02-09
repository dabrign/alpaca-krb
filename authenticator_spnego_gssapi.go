// Copyright 2024 The Alpaca Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build cgo && !purego

package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"

	_ "github.com/golang-auth/go-gssapi-c"
	"github.com/golang-auth/go-gssapi/v3"
)

// gssProvider is the GSS-API provider instance
var gssProvider gssapi.Provider

func init() {
	var err error
	gssProvider, err = gssapi.NewProvider("github.com/golang-auth/go-gssapi-c")
	if err != nil {
		// Don't fail at init - we'll check at runtime
		log.Printf("[GSSAPI] Warning: GSS-API provider not available: %v", err)
	}
}

// gssapiAuthenticator implements native GSS-API SPNEGO authentication
// that can access macOS Keychain credentials directly.
type gssapiAuthenticator struct {
	spn   string
	debug bool
	mu    sync.Mutex
}

// NewGSSAPIAuthenticator creates a new GSS-API based SPNEGO authenticator.
// This uses the native GSS-API library to access OS credential stores (e.g., macOS Keychain).
func NewGSSAPIAuthenticator(spn string, debug bool) (*gssapiAuthenticator, error) {
	if gssProvider == nil {
		return nil, fmt.Errorf("GSS-API provider not available - ensure CGO is enabled and GSS-API libraries are installed")
	}
	return &gssapiAuthenticator{
		spn:   spn,
		debug: debug,
	}, nil
}

// IsGSSAPIAvailable returns true if GSS-API is available on this system.
func IsGSSAPIAvailable() bool {
	return gssProvider != nil
}

// debugLog logs a message if debug mode is enabled.
func (g *gssapiAuthenticator) debugLog(format string, args ...interface{}) {
	if g.debug {
		log.Printf("[GSSAPI] "+format, args...)
	}
}

// Do performs SPNEGO/Kerberos authentication using native GSS-API.
func (g *gssapiAuthenticator) Do(req *http.Request, rt http.RoundTripper) (*http.Response, error) {
	g.debugLog("Generating SPNEGO token for SPN: %s", g.spn)

	token, err := g.getToken()
	if err != nil {
		log.Printf("Error getting GSS-API token: %v", err)
		return nil, err
	}
	g.debugLog("SPNEGO token generated successfully (length: %d)", len(token))

	req.Header.Set("Proxy-Authorization", "Negotiate "+token)
	g.debugLog("Sending request with Negotiate header to %s", req.URL.Host)

	resp, err := rt.RoundTrip(req)
	if err != nil {
		log.Printf("Error sending SPNEGO request: %v", err)
		return nil, err
	}

	g.debugLog("Response status: %d", resp.StatusCode)

	if resp.StatusCode == http.StatusProxyAuthRequired {
		authHeader := resp.Header.Get("Proxy-Authenticate")
		g.debugLog("Proxy-Authenticate header: %s", authHeader)
		log.Printf("Received 407 Proxy Authentication Required - check SPN (%s) is correct", g.spn)
	}

	return resp, nil
}

// getToken acquires a SPNEGO token using native GSS-API.
func (g *gssapiAuthenticator) getToken() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.debugLog("Importing target name: %s", g.spn)

	// Import the target name (SPN)
	targetName, err := gssProvider.ImportName(g.spn, gssapi.GSS_NT_HOSTBASED_SERVICE)
	if err != nil {
		return "", fmt.Errorf("failed to import SPN %q: %w", g.spn, err)
	}
	defer targetName.Release()

	g.debugLog("Initializing security context")

	// Initialize security context using default credentials (from Keychain on macOS)
	secctx, err := gssProvider.InitSecContext(targetName, gssapi.WithInitiatorFlags(gssapi.ContextFlagMutual))
	if err != nil {
		return "", fmt.Errorf("failed to initialize security context: %w", err)
	}
	defer secctx.Delete()

	g.debugLog("Getting initial token")

	// Get the initial token
	token, _, err := secctx.Continue(nil)
	if err != nil {
		return "", fmt.Errorf("failed to get SPNEGO token: %w", err)
	}

	g.debugLog("Token generated successfully")
	return base64.StdEncoding.EncodeToString(token), nil
}

// String returns a string representation for logging.
func (g *gssapiAuthenticator) String() string {
	return fmt.Sprintf("gssapi:native (SPN: %s)", g.spn)
}
