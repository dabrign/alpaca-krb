// Copyright 2019, 2021, 2024 The Alpaca Authors
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
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/samuong/go-ntlmssp"
)

// Authenticator is the interface for proxy authentication methods.
type Authenticator interface {
	// Do performs authentication for the given request.
	Do(req *http.Request, rt http.RoundTripper) (*http.Response, error)
	// String returns a string representation (for logging/debugging).
	String() string
}

// ntlmAuthenticator implements NTLM proxy authentication.
type ntlmAuthenticator struct {
	domain   string
	username string
	hash     []byte
}

// authenticator is an alias for backward compatibility with existing code.
// TODO: Remove this alias after updating all references.
type authenticator = ntlmAuthenticator

func (a *ntlmAuthenticator) Do(req *http.Request, rt http.RoundTripper) (*http.Response, error) {
	hostname, _ := os.Hostname() // in case of error, just use the zero value ("") as hostname
	negotiate, err := ntlmssp.NewNegotiateMessage(a.domain, hostname)
	if err != nil {
		log.Printf("Error creating NTLM Type 1 (Negotiate) message: %v", err)
		return nil, err
	}
	req.Header.Set("Proxy-Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiate))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		log.Printf("Error sending NTLM Type 1 (Negotiate) request: %v", err)
		return nil, err
	} else if resp.StatusCode != http.StatusProxyAuthRequired {
		log.Printf("Expected response with status 407, got %s", resp.Status)
		return resp, nil
	}
	resp.Body.Close()
	challenge, err := base64.StdEncoding.DecodeString(
		strings.TrimPrefix(resp.Header.Get("Proxy-Authenticate"), "NTLM "))
	if err != nil {
		log.Printf("Error decoding NTLM Type 2 (Challenge) message: %v", err)
		return nil, err
	}
	authenticate, err := ntlmssp.ProcessChallengeWithHash(
		challenge, a.domain, a.username, a.hash)
	if err != nil {
		log.Printf("Error processing NTLM Type 2 (Challenge) message: %v", err)
		return nil, err
	}
	req.Header.Set("Proxy-Authorization",
		"NTLM "+base64.StdEncoding.EncodeToString(authenticate))
	return rt.RoundTrip(req)
}

func (a *ntlmAuthenticator) String() string {
	return fmt.Sprintf("%s@%s:%s", a.username, a.domain, hex.EncodeToString(a.hash))
}

// do is kept for backward compatibility with existing code that uses value receiver.
func (a authenticator) do(req *http.Request, rt http.RoundTripper) (*http.Response, error) {
	return (&a).Do(req, rt)
}
