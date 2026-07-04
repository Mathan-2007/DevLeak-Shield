# 🛡️ DevLeakShield

> **AI Prompt Firewall & Secret Protection for Visual Studio Code**

DevLeakShield is a cybersecurity extension for Visual Studio Code that protects developers from accidentally exposing sensitive information such as API keys, passwords, JWT tokens, cloud credentials, database secrets, and private keys while coding or using AI assistants.

Designed for developers, cybersecurity learners, DevSecOps engineers, and teams who use modern AI-powered development workflows.

---

# 🚀 Install

Install directly from the Visual Studio Code Marketplace.

```bash
code --install-extension mathan09072007.dev-leak-shield
```

Or manually:

```text
VS Code
   ↓
Extensions
   ↓
Search "DevLeakShield"
   ↓
Install
```

No configuration required.

DevLeakShield starts protecting immediately after installation.

---

# 🔥 Why DevLeakShield?

Modern developers use AI tools every day:

```text
Developer
    |
    v
ChatGPT
Claude
Gemini
GitHub Copilot
Cursor
```

But copying source code can accidentally expose:

```text
API Keys
Passwords
Tokens
JWT Secrets
Cloud Keys
Database URLs
Private Keys
```

DevLeakShield adds a security layer before secrets leave your machine.

---

# 🔑 Automatic Security Initialization

After installation:

```text
Install Extension
        |
        v
Create Secure Encryption Key
        |
        v
Store Key Securely
        |
        v
Enable Secret Protection
```

Features:

- Automatic encryption key generation
- Persistent local secure storage
- No manual setup
- No configuration files required

If the security key is removed:

```text
Missing Key
     |
     v
Generate New Key
     |
     v
Create New Secure Vault
```

DevLeakShield automatically restores protection.

---

# 🧠 AI Prompt Firewall

Protects code before sending it to AI tools.

Supported workflows:

- ChatGPT
- Claude
- Gemini
- GitHub Copilot
- Cursor
- AI coding assistants

Protection flow:

```text
Copied Code
     |
     v
AI Firewall
     |
     v
Secret Scanner
     |
     v
Safe Output
```

Example:

Before:

```env
OPENAI_API_KEY=sk-real-secret-value
DATABASE_PASSWORD=root12345
```

After DevLeakShield:

```env
OPENAI_API_KEY=[REDACTED_TOKEN]
DATABASE_PASSWORD=[REDACTED_SECRET]
```

---

# 🔍 Secret Detection Engine

Detects:

```text
✔ OpenAI API Keys

✔ GitHub Tokens

✔ AWS Credentials

✔ Azure Secrets

✔ Google Cloud Keys

✔ JWT Tokens

✔ SSH Private Keys

✔ Database URLs

✔ Passwords

✔ Environment Variables

✔ High Entropy Secrets
```

---

# ⚡ Status Bar Controls

After installation DevLeakShield appears in the VS Code bottom bar.

```text
● Secure Copy

● AI Mode
```

Click:

```text
Secure Copy
```

Enable or disable protected copy mode.

Click:

```text
AI Mode
```

Enable AI-safe protection.

---

# 🖱️ Right Click Security Actions

Select code.

Right click.

Available commands:

```text
DevLeakShield: Toggle Secure Copy Mode

DevLeakShield: Toggle AI Mode

DevLeakShield: Generate Security Report
```

No terminal commands required.

---

# 🔐 Secure Copy Protection

Normal copy:

```text
Secret
  |
  v
Clipboard
  |
  v
Possible Leak
```

With DevLeakShield:

```text
Secret
  |
  v
Detection Engine
  |
  v
Secure Vault
  |
  v
Protected Output
```

---

# 🔒 Secure Vault

Security architecture:

```text
Sensitive Data
      |
      v
AES-256-GCM Encryption
      |
      v
Secure Storage
      |
      v
Token Reference
```

Includes:

- AES-256-GCM encryption
- Local secure storage
- Token mapping
- Session protection

Secrets are never stored directly in clipboard content.

---

# 📊 Security Reports

Generate security analysis:

Right click:

```text
DevLeakShield: Generate Security Report
```

Example:

```text
Security Report

Files scanned : 120

Secrets found : 5

Risk Level : HIGH

Protection : ACTIVE
```

---

# 🧬 Git Protection

Prevents committing secrets.

Example:

```bash
git commit -m "update config"
```

DevLeakShield checks for sensitive exposure before secrets reach repositories.

Detects:

```text
.env leaks
Hardcoded credentials
Private keys
Tokens
```

---

# 📂 Architecture

```text
src
 |
 ├── core
 |     |
 |     ├── crypto
 |     |
 |     ├── secrets
 |     |
 |     └── reports
 |
 ├── ui
 |
 └── extension.ts
```

---

# 🛠️ Technology Stack

Built with:

```text
TypeScript

Node.js

Visual Studio Code API

AES-256-GCM Encryption

Secure Storage

Secret Detection Engine
```

---

# 🧪 Development

Clone:

```bash
git clone https://github.com/Mathan-2007/DevLeakShield.git
```

Enter project:

```bash
cd DevLeakShield
```

Install:

```bash
npm install
```

Compile:

```bash
npm run compile
```

Package:

```bash
npx vsce package
```

---

# 🌟 Roadmap

Upcoming features:

```text
Enterprise Dashboard

Secret Rotation

SIEM Integration

Cloud Vault Support

GitHub Actions Security

Advanced AI Security Rules

Team Policy Management
```

---

# 🤝 Contributing

Security improvements, bug reports, and feature suggestions are welcome.

Fork the repository:

```bash
git fork
```

Create changes:

```bash
git checkout -b feature-name
```

Submit pull request.

---

# 📜 License

MIT License

---

# 👨‍💻 Author

```text
Mathan S

Cybersecurity Enthusiast

Developer Security Tools

AI Security Research
```

GitHub:

```text
https://github.com/Mathan-2007
```

---

⭐ If DevLeakShield helps secure your workflow, consider supporting the project.
