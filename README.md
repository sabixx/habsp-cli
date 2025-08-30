# habsp-cli

Small, cross-platform uploader for **HaveIbeenSSHpwned**.  
It scans a file or folder for **SSH public keys**, refuses to run if it detects a **private key**, then uploads the public keys to the service using a rate-limited API.

## Features

- 🔍 Scans files/folders for OpenSSH **public keys** (deduplicates).
- 🛑 Stops immediately if a **private key** is detected.
- 🔐 Keycloak auth: **device flow** (default) or **password**.
- 📶 Friendly HUD with progress bar + ETA; optional `--debug` shows pool/active/waiting stats.
- 🔒 TLS options: custom CA bundle or `--insecure` for testing.

---

## Quick start

### Build (Go 1.21+)

```bash
go build -o habsp-cli .


### Upload with device auth (recommended)
./habsp-cli device --path ~/.ssh


.\habsp-cli-windows-amd64.exe --auth password `
  --user "you@example.com" --password "••••" `
  --path ".\keys\public\mykey.pub"
