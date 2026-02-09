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

//go:build !cgo || purego

package main

import (
	"fmt"
	"net/http"
)

// gssapiAuthenticator stub for non-CGO builds
type gssapiAuthenticator struct {
	spn   string
	debug bool
}

// NewGSSAPIAuthenticator returns an error when CGO is not available.
func NewGSSAPIAuthenticator(spn string, debug bool) (*gssapiAuthenticator, error) {
	return nil, fmt.Errorf("GSS-API not available: built without CGO support. Use password, keytab, or credential cache authentication instead")
}

// IsGSSAPIAvailable returns false when CGO is not available.
func IsGSSAPIAvailable() bool {
	return false
}

// Do is a stub that should never be called.
func (g *gssapiAuthenticator) Do(req *http.Request, rt http.RoundTripper) (*http.Response, error) {
	return nil, fmt.Errorf("GSS-API not available: built without CGO support")
}

// String returns a string representation for logging.
func (g *gssapiAuthenticator) String() string {
	return "gssapi:unavailable"
}
