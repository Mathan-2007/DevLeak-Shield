export type SecretCategory =
  | "openai"
  | "aws"
  | "github"
  | "jwt"
  | "ssh"
  | "database"
  | "api_key"
  | "generic";

export interface SecretFinding {
  value: string;
  category: SecretCategory;
  location: {
    filePath?: string;
    line?: number;
    column?: number;
  };
  detection: {
    regexMatch: boolean;
    entropyScore: number;
    contextScore: number;
    confidence: number;
    risk: number;
    features: string[];
  };
}

export interface DetectionResult {
  findings: SecretFinding[];
  maxRisk: number;
  summary: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  threshold: number;
  categories: SecretCategory[];
  enabled: boolean;
  allowlist: string[];
  denylist: string[];
}

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
  ruleId?: string;
  risk: number;
}

export interface VaultConfig {
  encryptedPayload?: string;
  sessionMode?: boolean;
  passwordProtected?: boolean;
}

export interface FirewallContext {
  source: "clipboard" | "ai" | "git";
  text: string;
  origin?: string;
}

export interface ReportSummary {
  totalFindings: number;
  riskDistribution: Record<string, number>;
  score: number;
  generatedAt: string;
}

export interface ReportPayload {
  summary: ReportSummary;
  findings: SecretFinding[];
  policyRules: PolicyRule[];
}

export type ClipboardAction = "secure_copy" | "secure_paste" | "encrypt_selection" | "decrypt_selection" | "blocked_copy" | "blocked_paste";

export interface ClipboardAuditRecord {
  action: ClipboardAction;
  timestamp: string;
  riskScore: number;
  secretTypes: SecretCategory[];
  success: boolean;
  reason?: string;
  itemCount: number;
}

export interface ClipboardAuditSummary {
  totalEvents: number;
  blockedCopyAttempts: number;
  encryptedSecretsCount: number;
  decryptedPasteCount: number;
}

/**
 * Vault Entry: Encrypted secret storage with token mapping
 * Token contains NO plaintext, encryption key, IV, or reversible data
 * Token is ONLY a vault reference identifier
 */
export interface VaultEntry {
  tokenId: string; // UUID, used only as reference (e.g., "8f4c9e2d")
  encryptedSecret: string; // AES-256-GCM encrypted secret with IV and authTag
  createdAt: string; // ISO timestamp
  classification: SecretCategory; // openai, aws, github, etc.
  riskScore: number; // 0.0 to 1.0
  metadata?: {
    source?: string; // where secret was detected
    filePath?: string; // where it came from
    expiresAt?: string; // optional expiration
  };
}

/**
 * Vault metadata: Index of all stored entries
 * Encrypted at rest inside VS Code SecretStorage
 */
export interface VaultMetadata {
  version: number; // For schema evolution
  entriesCount: number;
  createdAt: string;
  lastModified: string;
}

export interface VaultStoreResult {
  token: string; // DEVLEAKSHIELD_TOKEN_<tokenId>
  tokenId: string;
  classification: SecretCategory;
  riskScore: number;
}

export interface VaultRetrieveResult {
  found: boolean;
  secret?: string; // Only if token is valid and vault entry exists
  classification?: SecretCategory;
  riskScore?: number;
  error?: string;
}
