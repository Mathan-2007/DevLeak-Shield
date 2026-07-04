# DevLeakShield

> **Enterprise-grade AI-safe secret protection for Visual Studio Code**

DevLeakShield is a Visual Studio Code extension that helps developers prevent accidental exposure of sensitive information such as API keys, passwords, JWTs, private keys, database credentials, and access tokens when working with source code or AI assistants like ChatGPT, Claude, Gemini, GitHub Copilot, and Cursor.

---

# Features

## Secret Detection

Detects a wide range of secrets including:

* API Keys
* OpenAI Keys
* GitHub Personal Access Tokens
* AWS Access Keys
* Azure Credentials
* Google Cloud Credentials
* JWT Tokens
* SSH Private Keys
* Database Connection Strings
* OAuth Secrets
* Environment Variables
* Passwords
* Generic High-Entropy Secrets

---

## AI Prompt Firewall

Before content is copied to an AI assistant, DevLeakShield scans it for sensitive information and alerts you if secrets are detected.

Supported AI tools include:

* ChatGPT
* Claude
* Gemini
* GitHub Copilot
* Cursor
* Continue
* Other AI-powered coding assistants

---

## Secure Copy

When sensitive information is detected:

* Prevents accidental exposure
* Stores the secret securely
* Replaces clipboard content with a secure reference
* Reduces the risk of credential leaks

---

## Secure Paste

Safely restores protected secrets only inside trusted environments.

---

## Encrypted Secret Vault

Features:

* AES-256-GCM Encryption
* UUID-based Secret Mapping
* Session Protection
* Password-Protected Vault
* Secure Local Storage

Secrets are never stored as plain text in the clipboard.

---

## Git Security

Prevent secrets from being committed.

Features:

* Git Pre-Commit Scanning
* Commit Blocking
* Risk Assessment
* Secret Detection Reports

---

## Policy Engine

Create organization-wide security policies.

Examples:

* Block High-Risk Secrets
* Warn on Medium-Risk Secrets
* Allow Low-Risk Operations
* Configure Allow Lists
* Configure Block Lists

---

## Security Dashboard

View security insights including:

* Total Secrets Detected
* Risk Distribution
* Scan History
* Detection Statistics
* Security Reports

---

# Security Workflow

```text
Developer
      │
      ▼
Secret Detection
      │
      ▼
Risk Analysis
      │
      ▼
Encrypted Vault
      │
      ▼
Secure Clipboard
      │
      ▼
Safe AI Sharing
```

---

# Commands

* DevLeakShield: Secure Copy
* DevLeakShield: Secure Paste
* DevLeakShield: Toggle AI Mode
* DevLeakShield: Generate Security Report
* DevLeakShield: Scan Workspace
* DevLeakShield: Git Pre-Commit Scan

---

# Technology Stack

* TypeScript
* Node.js
* Visual Studio Code Extension API
* AES-256-GCM Encryption
* Mocha
* npm

---

# Installation

## From VS Code Marketplace

Coming Soon.

## Manual Installation

Install the extension from a `.vsix` package:

```bash
code --install-extension devleakshield-1.0.5.vsix
```

---

# Development

Install dependencies:

```bash
npm install
```

Compile:

```bash
npm run compile
```

Run the Extension Development Host:

Press **F5** inside Visual Studio Code.

---

# Testing

Run tests:

```bash
npm test
```

Generate coverage:

```bash
npx nyc npm test
```

---

# Roadmap

* Enterprise Dashboard
* Secret Rotation
* Cloud Vault Support
* SIEM Integration
* GitHub Actions Integration
* RBAC Support
* Workspace Security Policies

---

# License

MIT License

---

# Author

**Mathan S**

Cybersecurity Enthusiast • Developer Security • Secure Coding Tools

GitHub:
https://github.com/Mathan-2007
