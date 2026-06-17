# DevLeakShield

Protect secrets before they leave your machine.

DevLeakShield is a VS Code extension designed to prevent accidental leakage of sensitive information such as API keys, passwords, tokens, credentials, private keys, and database connection strings.

---

## Features

### Secure Copy

Detects sensitive secrets during copy operations.

Instead of copying raw secrets:

```txt
sk-xxxxxxxxxxxxxxxxxxxxxxxx
```

DevLeakShield stores the secret in an encrypted vault and places a secure token on the clipboard.

---

### Secure Paste

Automatically restores vault-protected secrets when pasted inside trusted environments.

---

### Zero-Trust Vault Architecture

- AES-256-GCM Encryption
- Tokenized Secret References
- UUID-based Secret Mapping
- Session Key Protection

Secrets never travel through the clipboard in plaintext.

---

### AI Mode

Workspace-wide secret protection.

Features:

- Scan project files
- Detect sensitive data
- Replace secrets with vault references
- Safe AI sharing

---

### Secret Detection Engine

Detects:

- OpenAI Keys
- GitHub Tokens
- AWS Credentials
- Database URLs
- JWT Tokens
- SSH Keys
- API Keys
- Passwords
- OAuth Secrets
- Environment Variables

---

### Policy Engine

Configurable security policies.

Examples:

- Block high-risk secrets
- Warn on medium-risk findings
- Allow low-risk operations

---

### Git Security Scanning

Detect leaked secrets before they reach Git repositories.

---

## Security Architecture

DevLeakShield follows a Zero-Trust Security Model.

```txt
Secret
  ↓
Detection Engine
  ↓
Encrypted Vault
  ↓
UUID Token
  ↓
Clipboard
```

No secret is stored directly in clipboard content.

---

## Installation

### Marketplace

Coming Soon

### Manual Installation

Download:

```txt
dev-leak-shield.vsix
```

Install:

```bash
code --install-extension dev-leak-shield.vsix
```

---

## Commands

### DevLeakShield: Smart Copy

Securely copy detected secrets.

### DevLeakShield: Smart Paste

Restore encrypted secrets.

### DevLeakShield: Toggle AI Mode

Enable workspace protection.

### DevLeakShield: Generate Security Report

Create workspace security report.

---

## Technology Stack

- TypeScript
- VS Code Extension API
- AES-256-GCM Encryption
- Mocha
- Node.js

---

## Testing

Current Coverage:

- 27 Tests Passing
- ~80% Coverage

Run:

```bash
npm test
```

Coverage:

```bash
npx nyc npm test
```

---

## Roadmap

- Enterprise Dashboard
- RBAC
- SIEM Integration
- Secret Rotation
- Cloud Vault Support
- GitHub Actions Integration

---

## License

MIT License

---

## Author
Mathan
Mathan

Security Engineering & Developer Security Tools
