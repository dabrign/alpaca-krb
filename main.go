// Copyright 2019, 2021, 2022, 2025 The Alpaca Authors
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
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
)

var BuildVersion string

func whoAmI() string {
	me, err := user.Current()
	if err != nil {
		return ""
	}
	return me.Username
}

type stringArrayFlag []string

func (s *stringArrayFlag) String() string {
	return fmt.Sprintf("%v", *s)
}

func (s *stringArrayFlag) Set(value string) error {
	if value == "" {
		return nil
	}
	*s = append(*s, value)
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)

	var hosts stringArrayFlag
	flag.Var(&hosts, "l", "address to listen on")
	port := flag.Int("p", 3128, "port number to listen on")
	pacurl := flag.String("C", "", "url of proxy auto-config (pac) file")
	domain := flag.String("d", "", "domain of the proxy account (for NTLM auth)")
	username := flag.String("u", whoAmI(), "username of the proxy account (for NTLM auth)")
	keychainItem := flag.String("k", "", "keychain item label to use for credentials (macOS only)")
	printHash := flag.Bool("H", false, "print hashed NTLM credentials for non-interactive use")
	version := flag.Bool("version", false, "print version number")

	// Kerberos authentication flags
	authType := flag.String("auth-type", "ntlm", "authentication type: ntlm or kerberos")
	krb5Conf := flag.String("krb5-conf", "", "path to krb5.conf (default: /etc/krb5.conf)")
	krbRealm := flag.String("krb-realm", "", "Kerberos realm (can also be specified in --krb-user as user@REALM)")
	krbKeytab := flag.String("krb-keytab", "", "path to Kerberos keytab file")
	krbSPN := flag.String("krb-spn", "", "Kerberos service principal name for proxy (e.g., HTTP/proxy.corp.com)")
	krbCCache := flag.String("krb-ccache", "", "path to Kerberos credential cache file")
	krbUser := flag.String("krb-user", "", "Kerberos username (e.g., user@REALM or DOMAIN\\user)")
	krbPassword := flag.String("krb-password", "", "Kerberos password (or use KRB_PASSWORD env var)")
	krbNative := flag.Bool("krb-native", false, "use native GSS-API for Kerberos (macOS Keychain, requires CGO)")
	krbDebug := flag.Bool("krb-debug", false, "enable verbose Kerberos debug logging")

	flag.Parse()

	// default to localhost if no hosts are specified
	if len(hosts) == 0 {
		hosts = append(hosts, "localhost")
	}

	if *version {
		fmt.Println("Alpaca", BuildVersion)
		os.Exit(0)
	}

	var auth Authenticator

	// Handle Kerberos authentication
	if *authType == "kerberos" {
		// Use native GSS-API if requested
		if *krbNative {
			if !IsGSSAPIAvailable() {
				log.Fatalf("GSS-API not available. Build with CGO enabled or use password/keytab/ccache authentication.")
			}
			// For native GSS-API, we need the SPN
			spn := *krbSPN
			if spn == "" && *pacurl != "" {
				// Try to auto-discover SPN from PAC URL
				if u, err := url.Parse(*pacurl); err == nil && u.Hostname() != "" {
					spn = "HTTP/" + u.Hostname()
					log.Printf("Auto-discovered SPN from PAC URL: %s", spn)
				}
			}
			if spn == "" {
				log.Fatalf("SPN required for native GSS-API authentication. Use --krb-spn=HTTP/proxy.hostname")
			}
			var err error
			auth, err = NewGSSAPIAuthenticator(spn, *krbDebug)
			if err != nil {
				log.Fatalf("GSS-API authentication setup failed: %v", err)
			}
			log.Printf("Using native GSS-API authentication (SPN: %s)", spn)
		} else {
			// Use pure Go gokrb5 implementation
			krbSource := fromKerberosSource(KerberosOptions{
				Krb5Conf: *krb5Conf,
				Realm:    *krbRealm,
				Keytab:   *krbKeytab,
				SPN:      *krbSPN,
				Username: *krbUser,
				Password: *krbPassword,
				CCache:   *krbCCache,
				ProxyURL: *pacurl, // Use PAC URL for SPN auto-discovery if available
				Debug:    *krbDebug,
			})
			var err error
			auth, err = krbSource.getAuthenticator()
			if err != nil {
				log.Fatalf("Kerberos authentication setup failed: %v", err)
			}
		}
	} else {
		// NTLM authentication (default)
		var src credentialSource
		if *domain != "" {
			src = fromTerminal().forUser(*domain, *username)
		} else if value := os.Getenv("NTLM_CREDENTIALS"); value != "" {
			src = fromEnvVar(value)
		} else {
			src = fromKeyring(*keychainItem)
		}

		if src != nil {
			a, err := src.getCredentials()
			if err != nil {
				log.Printf("Credentials not found, disabling proxy auth: %v", err)
			} else {
				auth = a
			}
		}
	}

	if *printHash {
		if auth == nil {
			fmt.Println("Please specify a domain (using -d) and username (using -u)")
			os.Exit(1)
		}
		fmt.Printf("# Add this to your ~/.profile (or equivalent) and restart your shell\n")
		fmt.Printf("NTLM_CREDENTIALS=%q; export NTLM_CREDENTIALS\n", auth)
		os.Exit(0)
	}

	errch := make(chan error)

	s := createServer(*port, *pacurl, auth)
	for _, host := range hosts {
		address := net.JoinHostPort(host, strconv.Itoa(*port))
		for _, network := range networks(host) {
			go func(network string) {
				l, err := net.Listen(network, address)
				if err != nil {
					errch <- err
				} else {
					log.Printf("Listening on %s %s", network, address)
					errch <- s.Serve(l)
				}
			}(network)
		}
	}

	log.Fatal(<-errch)
}

func createServer(port int, pacurl string, auth Authenticator) *http.Server {
	pacWrapper := NewPACWrapper(PACData{Port: port})
	proxyFinder := NewProxyFinder(pacurl, pacWrapper)
	proxyHandler := NewProxyHandler(auth, getProxyFromContext, proxyFinder.blockProxy)
	mux := http.NewServeMux()
	pacWrapper.SetupHandlers(mux)

	// build the handler by wrapping middleware upon middleware
	var handler http.Handler = mux
	handler = RequestLogger(handler)
	handler = proxyHandler.WrapHandler(handler)
	handler = proxyFinder.WrapHandler(handler)
	handler = AddContextID(handler)

	return &http.Server{
		Handler: handler,
		// TODO: Implement HTTP/2 support. In the meantime, set TLSNextProto to a non-nil
		// value to disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
}

func networks(hostname string) []string {
	if hostname == "" {
		return []string{"tcp"}
	}
	addrs, err := net.LookupIP(hostname)
	if err != nil {
		log.Fatal(err)
	}
	nets := make([]string, 0, 2)
	ipv4 := false
	ipv6 := false
	for _, addr := range addrs {
		// addr == net.IPv4len doesn't work because all addrs use IPv6 format.
		if addr.To4() != nil {
			ipv4 = true
		} else {
			ipv6 = true
		}
	}
	if ipv4 {
		nets = append(nets, "tcp4")
	}
	if ipv6 {
		nets = append(nets, "tcp6")
	}
	return nets
}
