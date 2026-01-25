# Implementation Plan: Kerberos/SPNEGO Authentication

**Issue**: [#159 - Configurable keychain and Kerberos auth](https://github.com/samuong/alpaca/issues/159)

---

## Phase 1: Configurable Keychain Item (macOS)

### Tasks

- [x] **1.1 Add CLI flag for keychain item**
  - File: `main.go`
  - Add `-k` / `--keychain-item` flag
  - Example: `alpaca -k "kerberos:CORP.COM"`

- [x] **1.2 Refactor keyring_darwin.go**
  - Make keychain label configurable (remove hardcoded "NoMAD")
  - Add `readPasswordFromKeychainWithLabel(label string)` function
  - Support Kerberos SSO extension items (`kerberos:domain` format)

- [x] **1.3 Update credential source selection**
  - File: `main.go`
  - Accept keychain item from CLI flag
  - Pass to keyring constructor

- [x] **1.4 Add tests for configurable keychain**
  - File: `keyring_darwin_test.go`
  - Test custom label lookup
  - Test backward compatibility with NoMAD

- [x] **1.5 Update README.md**
  - Document new `-k` flag
  - Add examples for Kerberos SSO extension

---

## Phase 2: Kerberos/SPNEGO Authentication

### Tasks

- [ ] **2.1 Add gokrb5 dependency**
  - Add `github.com/jcmturner/gokrb5/v8` to `go.mod`
  - Run `go mod tidy`

- [ ] **2.2 Extract authenticator interface**
  - File: `authenticator.go`
  - Create `Authenticator` interface with `Do()` method
  - Rename existing struct to `ntlmAuthenticator`

- [ ] **2.3 Create SPNEGO authenticator**
  - File: `authenticator_spnego.go` (new)
  - Implement `spnegoAuthenticator` struct
  - Use gokrb5 SPNEGO client for token generation

- [ ] **2.4 Create Kerberos credential source**
  - File: `credentials_kerberos.go` (new)
  - Support ccache (ticket cache from `kinit`)
  - Support keytab files
  - Support password-based auth

- [ ] **2.5 Add Kerberos CLI flags**
  - File: `main.go`
  - `--auth-type`: `ntlm` | `kerberos` | `auto`
  - `--krb5-conf`: Path to krb5.conf
  - `--krb-realm`: Kerberos realm
  - `--krb-keytab`: Path to keytab
  - `--krb-spn`: Service Principal Name

- [ ] **2.6 Update proxy handler for Negotiate**
  - File: `proxy.go`
  - Detect `Negotiate` in `Proxy-Authenticate` header
  - Route to appropriate authenticator

- [ ] **2.7 Add SPNEGO tests**
  - File: `authenticator_spnego_test.go` (new)
  - Mock Negotiate proxy server
  - Test token generation

- [x] **2.8 Add Kerberos credential tests**
  - File: `credentials_kerberos_test.go` (new)
  - Test ccache loading
  - Test keytab loading

- [x] **2.9 Update README.md**
  - Add Kerberos usage section
  - Document all new flags
  - Add troubleshooting tips

---

## File Changes Summary

### Phase 1

| File | Action |
|------|--------|
| `main.go` | Add `-k` flag |
| `keyring_darwin.go` | Make keychain label configurable |
| `keyring_darwin_test.go` | Add tests |
| `README.md` | Document flag |

### Phase 2

| File | Action |
|------|--------|
| `go.mod` | Add gokrb5 dependency |
| `authenticator.go` | Extract interface, rename to ntlmAuthenticator |
| `authenticator_spnego.go` | **New** - SPNEGO implementation |
| `authenticator_spnego_test.go` | **New** - SPNEGO tests |
| `credentials_kerberos.go` | **New** - Kerberos credential source |
| `credentials_kerberos_test.go` | **New** - Kerberos tests |
| `main.go` | Add Kerberos CLI flags |
| `proxy.go` | Support Negotiate auth header |
| `README.md` | Kerberos documentation |

---

## CLI Examples (Target State)

```bash
# Phase 1: Custom keychain item
alpaca -k "kerberos:CORP.EXAMPLE.COM"

# Phase 2: Kerberos with existing ticket (kinit)
alpaca --auth-type kerberos

# Phase 2: Kerberos with explicit config
alpaca --auth-type kerberos \
       --krb5-conf /etc/krb5.conf \
       --krb-spn HTTP/proxy.corp.com

# Phase 2: Auto-detect (try Kerberos, fallback to NTLM)
alpaca --auth-type auto
```

---

## Progress Tracking

### Phase 1
- [x] Analysis complete
- [x] Implementation started
- [x] Tests passing
- [x] Documentation updated
- [x] Ready for review

#### Phase 1 Review Checklist
- [x] Code changes reviewed
- [x] Test coverage adequate
- [x] README documentation clear
- [x] Backward compatibility verified
- [x] Ready to commit
- [x] **Committed**: `b19554d` - feat: add configurable keychain item support (macOS)

### Phase 2
- [x] Analysis complete
- [ ] Implementation started
- [ ] Tests passing
- [ ] Documentation updated
- [ ] Ready for review
