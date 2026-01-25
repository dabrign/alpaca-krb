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
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// kerberosCredentialSource provides Kerberos credentials for SPNEGO authentication.
type kerberosCredentialSource struct {
	krb5Conf string // Path to krb5.conf
	realm    string // Kerberos realm (optional, can be inferred)
	keytab   string // Path to keytab file (optional)
	spn      string // Service Principal Name for the proxy
	username string // Username (optional, for password auth)
	password string // Password (optional, for password auth)
}

// KerberosOptions configures Kerberos credential source.
type KerberosOptions struct {
	Krb5Conf string
	Realm    string
	Keytab   string
	SPN      string
	Username string
	Password string
}

// fromKerberos creates a Kerberos credential source.
func fromKerberosSource(opts KerberosOptions) *kerberosCredentialSource {
	return &kerberosCredentialSource{
		krb5Conf: opts.Krb5Conf,
		realm:    opts.Realm,
		keytab:   opts.Keytab,
		spn:      opts.SPN,
		username: opts.Username,
		password: opts.Password,
	}
}

// getAuthenticator returns a SPNEGO authenticator using Kerberos.
func (k *kerberosCredentialSource) getAuthenticator() (Authenticator, error) {
	// Load krb5.conf
	cfg, err := k.loadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load Kerberos config: %w", err)
	}

	// Create Kerberos client based on available credentials
	var cl *client.Client

	if k.keytab != "" {
		// Use keytab file
		cl, err = k.clientFromKeytab(cfg)
	} else if k.password != "" {
		// Use password
		cl, err = k.clientFromPassword(cfg)
	} else {
		// Try credential cache (kinit)
		cl, err = k.clientFromCCache(cfg)
	}

	if err != nil {
		return nil, err
	}

	// Login to get TGT
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("Kerberos login failed: %w", err)
	}

	// Determine SPN
	spn := k.spn
	if spn == "" {
		return nil, fmt.Errorf("service principal name (SPN) is required for Kerberos authentication")
	}

	log.Printf("Kerberos authentication configured for %s (SPN: %s)", cl.Credentials.UserName(), spn)
	return NewSPNEGOAuthenticator(cl, spn), nil
}

// loadConfig loads the Kerberos configuration file.
func (k *kerberosCredentialSource) loadConfig() (*config.Config, error) {
	confPath := k.krb5Conf
	if confPath == "" {
		confPath = getDefaultKrb5ConfPath()
	}

	cfg, err := config.Load(confPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s: %w", confPath, err)
	}
	return cfg, nil
}

// clientFromCCache creates a client from the credential cache.
func (k *kerberosCredentialSource) clientFromCCache(cfg *config.Config) (*client.Client, error) {
	ccachePath := getDefaultCCachePath()

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load credential cache from %s: %w", ccachePath, err)
	}

	cl, err := client.NewFromCCache(ccache, cfg, client.DisablePAFXFAST(true))
	if err != nil {
		return nil, fmt.Errorf("failed to create Kerberos client from ccache: %w", err)
	}

	log.Printf("Using Kerberos credentials from cache: %s", ccachePath)
	return cl, nil
}

// clientFromKeytab creates a client from a keytab file.
func (k *kerberosCredentialSource) clientFromKeytab(cfg *config.Config) (*client.Client, error) {
	kt, err := keytab.Load(k.keytab)
	if err != nil {
		return nil, fmt.Errorf("failed to load keytab from %s: %w", k.keytab, err)
	}

	// Determine username and realm
	username := k.username
	realm := k.realm
	if realm == "" {
		realm = cfg.LibDefaults.DefaultRealm
	}

	if username == "" {
		// Try to get username from keytab entries
		if len(kt.Entries) > 0 {
			// Get principal components and join them
			components := kt.Entries[0].Principal.Components
			if len(components) > 0 {
				username = components[0]
			}
			if kt.Entries[0].Principal.Realm != "" {
				realm = kt.Entries[0].Principal.Realm
			}
		}
		if username == "" {
			return nil, fmt.Errorf("keytab has no entries and no username specified")
		}
	}

	cl := client.NewWithKeytab(username, realm, kt, cfg, client.DisablePAFXFAST(true))
	log.Printf("Using Kerberos credentials from keytab: %s (user: %s@%s)", k.keytab, username, realm)
	return cl, nil
}

// clientFromPassword creates a client using password authentication.
func (k *kerberosCredentialSource) clientFromPassword(cfg *config.Config) (*client.Client, error) {
	username := k.username
	realm := k.realm
	if realm == "" {
		realm = cfg.LibDefaults.DefaultRealm
	}

	if username == "" {
		return nil, fmt.Errorf("username is required for password-based Kerberos authentication")
	}

	cl := client.NewWithPassword(username, realm, k.password, cfg, client.DisablePAFXFAST(true))
	log.Printf("Using Kerberos password authentication for %s@%s", username, realm)
	return cl, nil
}

// getDefaultKrb5ConfPath returns the default path to krb5.conf.
func getDefaultKrb5ConfPath() string {
	if runtime.GOOS == "windows" {
		// Windows typically uses the registry or a file in the Kerberos installation
		if krbDir := os.Getenv("KRB5_CONFIG"); krbDir != "" {
			return krbDir
		}
		return filepath.Join(os.Getenv("WINDIR"), "krb5.ini")
	}
	// Unix-like systems
	if krbConf := os.Getenv("KRB5_CONFIG"); krbConf != "" {
		return krbConf
	}
	return "/etc/krb5.conf"
}

// getDefaultCCachePath returns the default path to the Kerberos credential cache.
func getDefaultCCachePath() string {
	// Check environment variable first
	if ccache := os.Getenv("KRB5CCNAME"); ccache != "" {
		// Handle FILE: prefix
		if len(ccache) > 5 && ccache[:5] == "FILE:" {
			return ccache[5:]
		}
		return ccache
	}

	// Default paths by OS
	if runtime.GOOS == "darwin" {
		// macOS uses a different default location
		if u, err := user.Current(); err == nil {
			// Try the API: path first (for Kerberos SSO extension)
			apiPath := fmt.Sprintf("/tmp/krb5cc_%s", u.Uid)
			if _, err := os.Stat(apiPath); err == nil {
				return apiPath
			}
		}
	}

	// Standard Unix path
	if u, err := user.Current(); err == nil {
		return fmt.Sprintf("/tmp/krb5cc_%s", u.Uid)
	}

	return "/tmp/krb5cc_0"
}
