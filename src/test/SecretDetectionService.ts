import { SecretDetectionService as CoreSecretDetectionService, CustomPatternRule } from "../core/secrets/SecretDetectionService";

export { CustomPatternRule };

export class SecretDetectionService extends CoreSecretDetectionService {
  constructor(customRules: CustomPatternRule[] = []) {
    super(customRules);
  }

  scan(text: string, filePath?: string) {
    return this.detect(text, filePath).findings;
  }
}
