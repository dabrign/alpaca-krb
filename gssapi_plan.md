# GSS-API Branch Implementation Plan

## Goal
Add native macOS Keychain support for Kerberos authentication using CGO + GSS-API.

## Library Choice: golang-auth/go-gssapi-c
- Actively maintained, modern Go modules (v3)
- Tested on macOS with Apple Kerberos
- Works with default Keychain - no extra packages needed

---

## Workplan

### Phase 1: Branch Setup
- [x] **1.1** Create branch `feature/gssapi-native`
- [x] **1.2** Add `golang-auth/go-gssapi/v3` dependency
- [x] **1.3** Add `golang-auth/go-gssapi-c` provider dependency

### Phase 2: Create GSS-API Authenticator
- [x] **2.1** Create `authenticator_spnego_gssapi.go` with build tag `//go:build cgo && !purego`
- [x] **2.2** Implement GSS-API SPNEGO token generation
- [x] **2.3** Add `--krb-native` flag to main.go

### Phase 3: Build Tag Organization
- [x] **3.1** Add build tag to pure-Go files: `//go:build !cgo || purego`
- [x] **3.2** Ensure both builds work

### Phase 4: Documentation & Testing
- [x] **4.1** Update README with CGO build instructions
- [ ] **4.2** Test with macOS default Apple Kerberos (requires valid Kerberos environment)

---

## Usage After Implementation

```bash
# macOS with native GSS-API (tickets from Keychain)
kinit user@REALM
alpaca --auth-type=kerberos --krb-native --krb-spn=HTTP/proxy.corp.com
```

## Build Commands

```bash
# Default (CGO enabled, uses GSS-API)
go build -o alpaca ./...

# Pure Go (no CGO, portable)
CGO_ENABLED=0 go build -tags purego -o alpaca ./...
```
