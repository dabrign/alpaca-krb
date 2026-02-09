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
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDefaultKrb5ConfPath(t *testing.T) {
	// Save and restore environment
	original := os.Getenv("KRB5_CONFIG")
	defer os.Setenv("KRB5_CONFIG", original)

	// Test with environment variable set
	os.Setenv("KRB5_CONFIG", "/custom/krb5.conf")
	path := getDefaultKrb5ConfPath()
	assert.Equal(t, "/custom/krb5.conf", path)

	// Test without environment variable
	os.Unsetenv("KRB5_CONFIG")
	path = getDefaultKrb5ConfPath()
	if runtime.GOOS == "windows" {
		assert.Contains(t, path, "krb5.ini")
	} else {
		assert.Equal(t, "/etc/krb5.conf", path)
	}
}

func TestGetCCachePath(t *testing.T) {
	// Save and restore environment
	original := os.Getenv("KRB5CCNAME")
	defer os.Setenv("KRB5CCNAME", original)

	src := fromKerberosSource(KerberosOptions{})

	// Test with explicit ccache path that exists
	tmpFile, err := os.CreateTemp("", "krb5cc_test")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	src.ccache = tmpFile.Name()
	path, err := src.getCCachePath()
	assert.NoError(t, err)
	assert.Equal(t, tmpFile.Name(), path)

	// Test with explicit ccache path that doesn't exist
	src.ccache = "/nonexistent/path"
	_, err = src.getCCachePath()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Reset explicit path for env var tests
	src.ccache = ""

	// Test with KCM: cache type (unsupported)
	os.Setenv("KRB5CCNAME", "KCM:1000")
	_, err = src.getCCachePath()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	// Test with API: cache type (unsupported)
	os.Setenv("KRB5CCNAME", "API:principal")
	_, err = src.getCCachePath()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	// Test with FILE: prefix and existing file
	os.Setenv("KRB5CCNAME", "FILE:"+tmpFile.Name())
	// Recreate the file since we deleted it
	tmpFile2, err := os.Create(tmpFile.Name())
	assert.NoError(t, err)
	tmpFile2.Close()
	path, err = src.getCCachePath()
	assert.NoError(t, err)
	assert.Equal(t, tmpFile.Name(), path)

	// Test with FILE: prefix but missing file
	os.Setenv("KRB5CCNAME", "FILE:/nonexistent/ccache")
	_, err = src.getCCachePath()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestKerberosCredentialSourceRequiresSPN(t *testing.T) {
	src := fromKerberosSource(KerberosOptions{
		Krb5Conf: "/etc/krb5.conf",
		// No SPN provided
	})

	// This should fail because no ccache exists and no SPN
	_, err := src.getAuthenticator()
	assert.Error(t, err)
}

func TestSPNAutoDiscovery(t *testing.T) {
	// Test with explicit SPN
	src := fromKerberosSource(KerberosOptions{
		SPN: "HTTP/proxy.corp.com",
	})
	spn, err := src.resolveSPN()
	assert.NoError(t, err)
	assert.Equal(t, "HTTP/proxy.corp.com", spn)

	// Test with proxy URL for auto-discovery
	src = fromKerberosSource(KerberosOptions{
		ProxyURL: "http://proxy.example.com:8080",
	})
	spn, err = src.resolveSPN()
	assert.NoError(t, err)
	assert.Equal(t, "HTTP/proxy.example.com", spn)

	// Test with no SPN and no proxy URL
	src = fromKerberosSource(KerberosOptions{})
	_, err = src.resolveSPN()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SPN")
}

func TestKerberosOptionsConstruction(t *testing.T) {
	opts := KerberosOptions{
		Krb5Conf: "/custom/krb5.conf",
		Realm:    "CORP.EXAMPLE.COM",
		Keytab:   "/path/to/user.keytab",
		SPN:      "HTTP/proxy.corp.com",
		Username: "testuser",
		CCache:   "/tmp/custom_ccache",
		ProxyURL: "http://proxy:8080",
		Debug:    true,
	}

	src := fromKerberosSource(opts)

	assert.Equal(t, "/custom/krb5.conf", src.krb5Conf)
	assert.Equal(t, "CORP.EXAMPLE.COM", src.realm)
	assert.Equal(t, "/path/to/user.keytab", src.keytab)
	assert.Equal(t, "HTTP/proxy.corp.com", src.spn)
	assert.Equal(t, "testuser", src.username)
	assert.Equal(t, "/tmp/custom_ccache", src.ccache)
	assert.Equal(t, "http://proxy:8080", src.proxyURL)
	assert.True(t, src.debug)
}
