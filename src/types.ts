export type SecretCategory =
  | "openai"
  | "anthropic"
  | "aws"
  | "github"
  | "jwt"
  | "ssh"
  | "database"
  | "api_key"
  | "generic"
  | "private_key"
  | "stripe"
  | "slack"
  | "discord"
  | "firebase"
  | "kubernetes"
  | "docker"
  | "azure"
  | "npm"
  | "gitlab"
  | "shopify"
  | "heroku"
  | "sendgrid"
  | "mailgun"
  | "telegram"
  | "twilio"
  | "google"
  | "password"
  | "bearer"
  | "access_token"
  | "cookie"
  | "custom";

export interface SecretFinding {
  value: string;
  category: SecretCategory;
  filePath?: string;
  line?: number;
  column?: number;
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

export interface ReportSummary {
  totalFindings: number;
  riskDistribution: Record<string, number>;
  score: number;
  generatedAt: string;
}

export interface ReportPayload {
  summary: ReportSummary;
  findings: SecretFinding[];
}
