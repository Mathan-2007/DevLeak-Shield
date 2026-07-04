# 🛡️ DevLeakShield

> Editor Copy Protection & Secret Detection for Visual Studio Code

DevLeakShield helps protect secrets before they leave the editor. It masks copied values, scans open documents for exposed credentials, and produces auditable reports for team workflows.

Protects everywhere you copy inside VS Code — Copilot Chat included.

## 🚀 Install

```bash
code --install-extension mathan0072007.dev-leak-shield
```

Current version: 1.0.6

## 🔐 What it does

- Secure Copy mode redacts secrets before they reach the clipboard.
- AI Mode masks secrets in open editor tabs for Copilot Chat and other AI workflows.
- Security reports can be generated and exported as JSON or CSV.
- Team policy rules can be extended through a repo-level config file.

## 🧭 Current implementation status

DevLeakShield is currently a leak-reduction tool for VS Code. It is designed to reduce accidental secret exposure during copy/paste and AI-assisted workflows.

It does not claim to be a full secret vault, a zero-trust platform, or a replacement for secret management services. The current implementation focuses on detection, masking, and reporting rather than enforcing a hardened remote policy system.

## 🧩 Custom policy file

Create a file named .devleakshield.yml in your workspace root:

```yaml
customPatterns:
  - name: "Internal API Key"
    pattern: "INTERNAL_[A-Z0-9]{20}"
```

The scanner will honor those patterns alongside the built-in secret rules.

## 📊 Security reports

Use the command palette or editor context menu to run:

- DevLeakShield: Generate Security Report
- DevLeakShield: Export Findings as JSON/CSV

## 🧪 Benchmark

Benchmark result: 100% precision on 50 benchmark files (50 true positives, 0 false positives) using locally generated sample files with known secrets and benign controls.

## 🎬 Demo

![DevLeakShield demo](images/devleakshield-demo.gif)

The demo shows the flow from secure copy to a redacted clipboard and a blocked commit workflow.

## 🛠️ Development

```bash
git clone https://github.com/Mathan-2007/DevLeak-Shield.git
cd DevLeak-Shield
npm install
npm run compile
npm test
```

## 📜 License

MIT License
