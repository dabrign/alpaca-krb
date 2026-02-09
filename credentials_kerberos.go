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
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

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
	username string // Username for password auth (can include @REALM)
	password string // Password for password auth
	ccache   string // Path to credential cache file (optional)
	proxyURL string // Proxy URL for SPN auto-discovery
	debug    bool   // Enable debug logging
}

// KerberosOptions configures Kerberos credential source.
type KerberosOptions struct {
	Krb5Conf string
	Realm    string
	Keytab   string
	SPN      string
	Username string // Username (can be user@REALM format)
	Password string // Password (or use KRB_PASSWORD env var)
	CCache   string // Explicit credential cache path
	ProxyURL string // Proxy URL for SPN auto-discovery
	Debug    bool   // Enable debug logging
}

// fromKerberos creates a Kerberos credential source.
func fromKerberosSource(opts KerberosOptions) *kerberosCredentialSource {
	// Check for password in environment variable if not provided
	password := opts.Password
	if password == "" {
		password = os.Getenv("KRB_PASSWORD")
	}

	return &kerberosCredentialSource{
		krb5Conf: opts.Krb5Conf,
		realm:    opts.Realm,
		keytab:   opts.Keytab,
		spn:      opts.SPN,
		username: opts.Username,
		password: password,
		ccache:   opts.CCache,
		proxyURL: opts.ProxyURL,
		debug:    opts.Debug,
	}
}

// debugLog logs a message if debug mode is enabled.
func (k *kerberosCredentialSource) debugLog(format string, args ...interface{}) {
	if k.debug {
		log.Printf("[KRB5] "+format, args...)
	}
}

// getAuthenticator returns a SPNEGO authenticator using Kerberos.
func (k *kerberosCredentialSource) getAuthenticator() (Authenticator, error) {
	k.debugLog("Starting Kerberos authentication setup")

	// Load krb5.conf
	cfg, err := k.loadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load Kerberos config: %w", err)
	}

	// Create Kerberos client based on available credentials
	// Priority: password > keytab > ccache (password is simplest, no external setup needed)
	var cl *client.Client

	if k.password != "" && k.username != "" {
		k.debugLog("Using password authentication (user: %s)", k.username)
		cl, err = k.clientFromPassword(cfg)
	} else if k.keytab != "" {
		k.debugLog("Using keytab file: %s", k.keytab)
		cl, err = k.clientFromKeytab(cfg)
	} else {
		k.debugLog("Using credential cache")
		cl, err = k.clientFromCCache(cfg)
	}

	if err != nil {
		return nil, err
	}

	// Login to get TGT
	k.debugLog("Logging in to obtain TGT")
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("Kerberos login failed: %w", err)
	}
	k.debugLog("TGT obtained successfully")

	// Determine SPN
	spn, err := k.resolveSPN()
	if err != nil {
		return nil, err
	}

	log.Printf("Kerberos authentication configured for %s@%s (SPN: %s)",
		cl.Credentials.UserName(), cl.Credentials.Domain(), spn)
	return NewSPNEGOAuthenticator(cl, spn, k.debug), nil
}

// loadConfig loads the Kerberos configuration file.
func (k *kerberosCredentialSource) loadConfig() (*config.Config, error) {
	confPath := k.krb5Conf
	if confPath == "" {
		confPath = getDefaultKrb5ConfPath()
	}
	k.debugLog("Loading krb5.conf from: %s", confPath)

	cfg, err := config.Load(confPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s: %w", confPath, err)
	}
	k.debugLog("Default realm: %s", cfg.LibDefaults.DefaultRealm)
	return cfg, nil
}

// resolveSPN determines the Service Principal Name to use.
func (k *kerberosCredentialSource) resolveSPN() (string, error) {
	// If explicitly provided, use it
	if k.spn != "" {
		k.debugLog("Using provided SPN: %s", k.spn)
		return k.spn, nil
	}

	// Try to auto-discover from proxy URL
	if k.proxyURL != "" {
		u, err := url.Parse(k.proxyURL)
		if err == nil && u.Hostname() != "" {
			spn := "HTTP/" + u.Hostname()
			k.debugLog("Auto-generated SPN from proxy URL: %s", spn)
			log.Printf("Auto-generated SPN from proxy: %s", spn)
			return spn, nil
		}
	}

	return "", fmt.Errorf("service principal name (SPN) is required for Kerberos authentication.\n" +
		"  Use --krb-spn to specify the SPN (e.g., --krb-spn=HTTP/proxy.corp.com)\n" +
		"  The SPN format is typically HTTP/<proxy-fqdn>")
}

// getCCachePath determines the credential cache path to use.
func (k *kerberosCredentialSource) getCCachePath() (string, error) {
	// 1. Explicit flag takes priority
	if k.ccache != "" {
		k.debugLog("Using explicit ccache path: %s", k.ccache)
		if _, err := os.Stat(k.ccache); err != nil {
			return "", fmt.Errorf("specified credential cache not found: %s", k.ccache)
		}
		return k.ccache, nil
	}

	// 2. Environment variable
	if ccache := os.Getenv("KRB5CCNAME"); ccache != "" {
		k.debugLog("Found KRB5CCNAME environment variable: %s", ccache)

		// Check for unsupported cache types on macOS
		if strings.HasPrefix(ccache, "KCM:") || strings.HasPrefix(ccache, "API:") {
			cacheType := strings.Split(ccache, ":")[0]
			return "", fmt.Errorf(
				"credential cache type %q is not supported by the pure Go Kerberos library.\n"+
					"  On macOS, you must use a file-based credential cache:\n"+
					"    1. Set: export KRB5CCNAME=FILE:/tmp/krb5cc_$(id -u)\n"+
					"    2. Run: kinit your.username@REALM\n"+
					"    3. Then run alpaca again\n"+
					"  Or specify the cache path directly: --krb-ccache=/path/to/ccache",
				cacheType)
		}

		path := ccache
		if strings.HasPrefix(ccache, "FILE:") {
			path = ccache[5:]
		}

		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("credential cache file not found: %s (from KRB5CCNAME)\n"+
				"  Run 'kinit' to obtain Kerberos tickets first", path)
		}
		k.debugLog("Using ccache from KRB5CCNAME: %s", path)
		return path, nil
	}

	// 3. Default file path
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("cannot determine current user: %w", err)
	}

	defaultPath := fmt.Sprintf("/tmp/krb5cc_%s", u.Uid)
	k.debugLog("Checking default ccache path: %s", defaultPath)

	if _, err := os.Stat(defaultPath); err != nil {
		// Provide helpful error message for macOS users
		if runtime.GOOS == "darwin" {
			return "", fmt.Errorf(
				"no credential cache found at default location: %s\n\n"+
					"  On macOS, Kerberos tickets are stored in the Keychain by default,\n"+
					"  but this tool requires a file-based credential cache.\n\n"+
					"  To fix this:\n"+
					"    1. Set the cache location:  export KRB5CCNAME=FILE:%s\n"+
					"    2. Obtain tickets:          kinit your.username@REALM\n"+
					"    3. Verify:                  klist\n"+
					"    4. Run alpaca again\n\n"+
					"  Or specify the cache path directly: --krb-ccache=/path/to/ccache",
				defaultPath, defaultPath)
		}
		return "", fmt.Errorf(
			"no credential cache found at: %s\n"+
				"  Run 'kinit your.username@REALM' to obtain Kerberos tickets first\n"+
				"  Or specify the cache path directly: --krb-ccache=/path/to/ccache",
			defaultPath)
	}

	k.debugLog("Using default ccache: %s", defaultPath)
	return defaultPath, nil
}

// clientFromCCache creates a client from the credential cache.
func (k *kerberosCredentialSource) clientFromCCache(cfg *config.Config) (*client.Client, error) {
	ccachePath, err := k.getCCachePath()
	if err != nil {
		return nil, err
	}

	k.debugLog("Loading credential cache from: %s", ccachePath)
	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load credential cache from %s: %w\n"+
			"  The cache file may be corrupted or in an unsupported format.\n"+
			"  Try running 'kinit' again to refresh your tickets.", ccachePath, err)
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
	k.debugLog("Loading keytab from: %s", k.keytab)
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

	k.debugLog("Using principal: %s@%s", username, realm)
	cl := client.NewWithKeytab(username, realm, kt, cfg, client.DisablePAFXFAST(true))
	log.Printf("Using Kerberos credentials from keytab: %s (user: %s@%s)", k.keytab, username, realm)
	return cl, nil
}

// clientFromPassword creates a client using password authentication.
// Username can be in "user" or "user@REALM" format.
func (k *kerberosCredentialSource) clientFromPassword(cfg *config.Config) (*client.Client, error) {
	username, realm := k.parseUsername(cfg)

	if username == "" {
		return nil, fmt.Errorf("username is required for password-based Kerberos authentication.\n" +
			"  Use --krb-user=username@REALM or --krb-user=username with --krb-realm=REALM")
	}

	if realm == "" {
		return nil, fmt.Errorf("Kerberos realm is required.\n" +
			"  Use --krb-user=username@REALM or specify --krb-realm=REALM\n" +
			"  Or ensure default_realm is set in /etc/krb5.conf")
	}

	k.debugLog("Authenticating user '%s' on realm '%s'", username, realm)
	cl := client.NewWithPassword(username, realm, k.password, cfg, client.DisablePAFXFAST(true))
	log.Printf("Using Kerberos password authentication for %s@%s", username, realm)
	return cl, nil
}

// parseUsername extracts username and realm from the configured username.
// Supports formats: "user", "user@REALM", "DOMAIN\\user"
func (k *kerberosCredentialSource) parseUsername(cfg *config.Config) (string, string) {
	username := k.username
	realm := k.realm

	// Handle user@REALM format
	if strings.Contains(username, "@") {
		parts := strings.SplitN(username, "@", 2)
		username = parts[0]
		if realm == "" && len(parts) > 1 {
			realm = strings.ToUpper(parts[1]) // Realms are typically uppercase
		}
	}

	// Handle DOMAIN\user format (Windows style)
	if strings.Contains(username, "\\") {
		parts := strings.SplitN(username, "\\", 2)
		if realm == "" {
			realm = strings.ToUpper(parts[0])
		}
		username = parts[1]
	}

	// Fall back to default realm from krb5.conf
	if realm == "" {
		realm = cfg.LibDefaults.DefaultRealm
	}

	return username, realm
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
