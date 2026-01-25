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

func TestGetDefaultCCachePath(t *testing.T) {
	// Save and restore environment
	original := os.Getenv("KRB5CCNAME")
	defer os.Setenv("KRB5CCNAME", original)

	// Test with environment variable set (FILE: prefix)
	os.Setenv("KRB5CCNAME", "FILE:/tmp/custom_ccache")
	path := getDefaultCCachePath()
	assert.Equal(t, "/tmp/custom_ccache", path)

	// Test with environment variable set (no prefix)
	os.Setenv("KRB5CCNAME", "/tmp/another_ccache")
	path = getDefaultCCachePath()
	assert.Equal(t, "/tmp/another_ccache", path)

	// Test without environment variable
	os.Unsetenv("KRB5CCNAME")
	path = getDefaultCCachePath()
	assert.Contains(t, path, "krb5cc_")
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

func TestKerberosOptionsConstruction(t *testing.T) {
	opts := KerberosOptions{
		Krb5Conf: "/custom/krb5.conf",
		Realm:    "CORP.EXAMPLE.COM",
		Keytab:   "/path/to/user.keytab",
		SPN:      "HTTP/proxy.corp.com",
		Username: "testuser",
	}

	src := fromKerberosSource(opts)

	assert.Equal(t, "/custom/krb5.conf", src.krb5Conf)
	assert.Equal(t, "CORP.EXAMPLE.COM", src.realm)
	assert.Equal(t, "/path/to/user.keytab", src.keytab)
	assert.Equal(t, "HTTP/proxy.corp.com", src.spn)
	assert.Equal(t, "testuser", src.username)
}
