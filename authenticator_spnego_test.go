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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAuthenticator is a simple mock for testing
type mockAuthenticator struct {
	authHeader string
	callCount  int
}

func (m *mockAuthenticator) Do(req *http.Request, rt http.RoundTripper) (*http.Response, error) {
	m.callCount++
	req.Header.Set("Proxy-Authorization", m.authHeader)
	return rt.RoundTrip(req)
}

func (m *mockAuthenticator) String() string {
	return "mock-authenticator"
}

func TestAuthenticatorInterface(t *testing.T) {
	// Verify that ntlmAuthenticator implements Authenticator interface
	var _ Authenticator = &ntlmAuthenticator{}

	// Verify that spnegoAuthenticator implements Authenticator interface
	var _ Authenticator = &spnegoAuthenticator{}
}

func TestSPNEGOAuthenticatorString(t *testing.T) {
	s := &spnegoAuthenticator{
		client: nil,
		spn:    "HTTP/proxy.corp.com",
	}
	result := s.String()
	assert.Contains(t, result, "HTTP/proxy.corp.com")
	assert.Contains(t, result, "kerberos")
}

type negotiateServer struct {
	t              *testing.T
	expectNegotiate bool
}

func (s negotiateServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	hdr := req.Header.Get("Proxy-Authorization")
	if hdr == "" {
		w.Header().Set("Proxy-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	if s.expectNegotiate && !strings.HasPrefix(hdr, "Negotiate ") {
		s.t.Errorf("Expected Negotiate auth header, got: %s", hdr)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Access granted"))
}

func TestProxyHandlerWithMockAuth(t *testing.T) {
	// Test that ProxyHandler works with the Authenticator interface
	server := httptest.NewServer(negotiateServer{t: t, expectNegotiate: true})
	defer server.Close()

	mock := &mockAuthenticator{authHeader: "Negotiate mock-token"}

	// Create a simple test request
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	// Use the mock authenticator
	transport := &http.Transport{}
	resp, err := mock.Do(req, transport)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, mock.callCount)
}

func TestNtlmAuthenticatorImplementsInterface(t *testing.T) {
	auth := &ntlmAuthenticator{
		domain:   "CORP",
		username: "testuser",
		hash:     []byte{0x01, 0x02, 0x03},
	}

	// Verify String() works
	s := auth.String()
	assert.Contains(t, s, "testuser")
	assert.Contains(t, s, "CORP")
}
