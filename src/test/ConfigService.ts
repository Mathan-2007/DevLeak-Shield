import { ConfigService as CoreConfigService } from "../core/config/ConfigService";

export class ConfigService {
  static loadCustomPatterns(workspaceRoot?: string) {
    return new CoreConfigService().loadCustomPatterns(workspaceRoot);
  }

  parse(content: string) {
    return new CoreConfigService().parse(content);
  }
}
