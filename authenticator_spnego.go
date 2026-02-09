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

package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// spnegoAuthenticator implements Kerberos/SPNEGO proxy authentication.
type spnegoAuthenticator struct {
	client *client.Client
	spn    string // Service Principal Name (e.g., HTTP/proxy.corp.com)
	debug  bool   // Enable debug logging
	mu     sync.Mutex
}

// NewSPNEGOAuthenticator creates a new SPNEGO authenticator with the given Kerberos client and SPN.
func NewSPNEGOAuthenticator(cl *client.Client, spn string, debug bool) *spnegoAuthenticator {
	return &spnegoAuthenticator{
		client: cl,
		spn:    spn,
		debug:  debug,
	}
}

// debugLog logs a message if debug mode is enabled.
func (s *spnegoAuthenticator) debugLog(format string, args ...interface{}) {
	if s.debug {
		log.Printf("[SPNEGO] "+format, args...)
	}
}

// Do performs SPNEGO/Kerberos authentication for the given request.
func (s *spnegoAuthenticator) Do(req *http.Request, rt http.RoundTripper) (*http.Response, error) {
	s.debugLog("Generating SPNEGO token for SPN: %s", s.spn)
	token, err := s.getToken()
	if err != nil {
		log.Printf("Error getting SPNEGO token: %v", err)
		return nil, err
	}
	s.debugLog("SPNEGO token generated successfully (length: %d)", len(token))

	req.Header.Set("Proxy-Authorization", "Negotiate "+token)
	s.debugLog("Sending request with Negotiate header to %s", req.URL.Host)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		log.Printf("Error sending SPNEGO request: %v", err)
		return nil, err
	}

	s.debugLog("Response status: %d", resp.StatusCode)

	// SPNEGO is typically single-round, but handle mutual auth if needed
	if resp.StatusCode == http.StatusProxyAuthRequired {
		// Check if server sent a continuation token (mutual authentication)
		authHeader := resp.Header.Get("Proxy-Authenticate")
		s.debugLog("Proxy-Authenticate header: %s", authHeader)
		if authHeader != "" && len(authHeader) > len("Negotiate ") {
			log.Printf("SPNEGO mutual authentication response received")
			// For now, we don't process the server's response token
			// Most proxies don't require mutual authentication
		}
		log.Printf("Received 407 Proxy Authentication Required - check SPN (%s) is correct", s.spn)
	}

	return resp, nil
}

// getToken acquires a SPNEGO token for the configured SPN.
func (s *spnegoAuthenticator) getToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.debugLog("Creating SPNEGO client for SPN: %s", s.spn)
	spnegoClient := spnego.SPNEGOClient(s.client, s.spn)

	s.debugLog("Acquiring credentials")
	if err := spnegoClient.AcquireCred(); err != nil {
		return "", fmt.Errorf("failed to acquire SPNEGO credentials: %w", err)
	}

	s.debugLog("Initializing security context")
	token, err := spnegoClient.InitSecContext()
	if err != nil {
		return "", fmt.Errorf("failed to initialize SPNEGO context: %w", err)
	}

	s.debugLog("Marshaling SPNEGO token")
	tokenBytes, err := token.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal SPNEGO token: %w", err)
	}

	s.debugLog("Token generated successfully")
	return base64.StdEncoding.EncodeToString(tokenBytes), nil
}

// String returns a string representation for logging.
func (s *spnegoAuthenticator) String() string {
	if s.client != nil && s.client.Credentials != nil {
		return fmt.Sprintf("kerberos:%s@%s (SPN: %s)",
			s.client.Credentials.UserName(),
			s.client.Credentials.Domain(),
			s.spn)
	}
	return fmt.Sprintf("kerberos:unknown (SPN: %s)", s.spn)
}
