// Copyright 2019, 2020, 2021 The Alpaca Authors
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
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/keybase/go-keychain"
	"github.com/samuong/go-ntlmssp"
)

type keyring struct {
	execCommand  func(name string, arg ...string) *exec.Cmd
	keychainItem string // Custom keychain item label (empty = use NoMAD)
}

func fromKeyring(keychainItem string) *keyring {
	return &keyring{execCommand: exec.Command, keychainItem: keychainItem}
}

func (k *keyring) readDefaultForNoMAD(key string) (string, error) {
	userDomain := "com.trusourcelabs.NoMAD"
	mpDomain := fmt.Sprintf("/Library/Managed Preferences/%s.plist", userDomain)

	// Read from managed preferences first
	out, err := k.execCommand("defaults", "read", mpDomain, key).Output()
	if err != nil {
		// Read from user preferences if not in managed preferences
		out, err = k.execCommand("defaults", "read", userDomain, key).Output()
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (k *keyring) readPasswordFromKeychain(userPrincipal string) string {
	return k.readPasswordFromKeychainWithLabel(userPrincipal, "NoMAD")
}

// readPasswordFromKeychainWithLabel reads a password from the keychain for a given account and label.
// If label is empty, it matches any label.
func (k *keyring) readPasswordFromKeychainWithLabel(account, label string) string {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetAccount(account)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)
	results, err := keychain.QueryItem(query)
	if err != nil || len(results) != 1 {
		return ""
	}
	// If a specific label is required, check it
	if label != "" && results[0].Label != label {
		return ""
	}
	return string(results[0].Data)
}

// readCredentialsFromKeychainItem reads credentials from a custom keychain item.
// The keychainItem format can be:
// - "label" - looks for an item with this label
// - "kerberos:REALM" - looks for Kerberos SSO extension credentials
func (k *keyring) readCredentialsFromKeychainItem(keychainItem string) (*authenticator, error) {
	// Handle Kerberos SSO extension format: "kerberos:REALM"
	if strings.HasPrefix(keychainItem, "kerberos:") {
		realm := strings.TrimPrefix(keychainItem, "kerberos:")
		return k.readKerberosCredentials(realm)
	}

	// Generic keychain item lookup by label
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetLabel(keychainItem)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, fmt.Errorf("keychain query failed: %w", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no keychain item found with label %q", keychainItem)
	}
	if len(results) > 1 {
		return nil, fmt.Errorf("multiple keychain items found with label %q", keychainItem)
	}

	// Parse account as user@domain
	account := results[0].Account
	substrs := strings.Split(account, "@")
	if len(substrs) != 2 {
		return nil, fmt.Errorf("keychain account %q is not in user@domain format", account)
	}
	user, domain := substrs[0], substrs[1]
	password := string(results[0].Data)
	hash := ntlmssp.GetNtlmHash(password)
	log.Printf("Found credentials for %s\\%s from keychain item %q", domain, user, keychainItem)
	return &authenticator{domain, user, hash}, nil
}

// readKerberosCredentials reads credentials from the Kerberos SSO extension keychain item.
func (k *keyring) readKerberosCredentials(realm string) (*authenticator, error) {
	// Kerberos SSO extension stores credentials with specific attributes
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService("kerberos:" + realm)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, fmt.Errorf("Kerberos keychain query failed: %w", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no Kerberos credentials found for realm %q", realm)
	}

	// Use the first matching result
	account := results[0].Account
	substrs := strings.Split(account, "@")
	if len(substrs) != 2 {
		return nil, fmt.Errorf("Kerberos account %q is not in user@realm format", account)
	}
	user, domain := substrs[0], substrs[1]
	password := string(results[0].Data)
	hash := ntlmssp.GetNtlmHash(password)
	log.Printf("Found Kerberos SSO credentials for %s\\%s", domain, user)
	return &authenticator{domain, user, hash}, nil
}

func (k *keyring) getCredentials() (*authenticator, error) {
	// If a custom keychain item is specified, use it
	if k.keychainItem != "" {
		return k.readCredentialsFromKeychainItem(k.keychainItem)
	}

	// Default: try NoMAD
	useKeychain, err := k.readDefaultForNoMAD("UseKeychain")
	if err != nil {
		return nil, err
	} else if useKeychain != "1" {
		return nil, errors.New("NoMAD found, but not configured to use keychain")
	}
	userPrincipal, err := k.readDefaultForNoMAD("UserPrincipal")
	if err != nil {
		return nil, err
	}
	substrs := strings.Split(userPrincipal, "@")
	if len(substrs) != 2 {
		return nil, errors.New("Couldn't retrieve AD domain and username from NoMAD.")
	}
	user, domain := substrs[0], substrs[1]
	hash := ntlmssp.GetNtlmHash(k.readPasswordFromKeychain(userPrincipal))
	log.Printf("Found NoMAD credentials for %s\\%s in system keychain", domain, user)
	return &authenticator{domain, user, hash}, nil
}
