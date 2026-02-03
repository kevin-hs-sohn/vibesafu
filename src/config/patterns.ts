/**
 * Security patterns for instant block and checkpoint detection
 */

import type { BlockPattern } from '../types.js';

// =============================================================================
// Instant Block Patterns - Always block without LLM
// =============================================================================

export const REVERSE_SHELL_PATTERNS: BlockPattern[] = [
  {
    name: 'bash_reverse_shell',
    pattern: /bash\s+-i\s+>&\s*\/dev\/tcp/i,
    severity: 'critical',
    description: 'Bash reverse shell via /dev/tcp',
  },
  {
    name: 'netcat_reverse_shell',
    pattern: /nc\s+.*-e\s+(\/bin\/)?(ba)?sh/i,
    severity: 'critical',
    description: 'Netcat reverse shell with -e flag',
  },
  {
    name: 'python_reverse_shell',
    pattern: /python[23]?\s+.*-c\s+.*socket.*connect/i,
    severity: 'critical',
    description: 'Python socket-based reverse shell',
  },
  {
    name: 'perl_reverse_shell',
    pattern: /perl\s+.*(-e\s+.*)?(['"])?use\s+Socket/i,
    severity: 'critical',
    description: 'Perl socket-based reverse shell',
  },
];

export const DATA_EXFIL_PATTERNS: BlockPattern[] = [
  {
    name: 'curl_api_key',
    pattern: /curl.*\$\{?[A-Z_]*KEY/i,
    severity: 'critical',
    description: 'curl with API key environment variable',
  },
  {
    name: 'curl_secret',
    pattern: /curl.*\$\{?[A-Z_]*SECRET/i,
    severity: 'critical',
    description: 'curl with secret environment variable',
  },
  {
    name: 'curl_token',
    pattern: /curl.*\$\{?[A-Z_]*TOKEN/i,
    severity: 'critical',
    description: 'curl with token environment variable',
  },
  {
    name: 'curl_password',
    pattern: /curl.*\$\{?[A-Z_]*PASSWORD/i,
    severity: 'critical',
    description: 'curl with password environment variable',
  },
  {
    name: 'curl_credential',
    pattern: /curl.*\$\{?[A-Z_]*CREDENTIAL/i,
    severity: 'critical',
    description: 'curl with credential environment variable',
  },
  {
    name: 'wget_key',
    pattern: /wget.*\$\{?[A-Z_]*KEY/i,
    severity: 'critical',
    description: 'wget with API key environment variable',
  },
  {
    name: 'wget_secret',
    pattern: /wget.*\$\{?[A-Z_]*SECRET/i,
    severity: 'critical',
    description: 'wget with secret environment variable',
  },
  {
    name: 'wget_token',
    pattern: /wget.*\$\{?[A-Z_]*TOKEN/i,
    severity: 'critical',
    description: 'wget with token environment variable',
  },
  {
    name: 'curl_data_env',
    pattern: /curl\s+.*(-d|--data|--data-raw)\s+.*\$\{?[A-Z_]/i,
    severity: 'critical',
    description: 'curl POST with environment variable in data',
  },
  {
    name: 'curl_header_env',
    pattern: /curl\s+.*(-H|--header)\s+.*\$\{?[A-Z_]/i,
    severity: 'critical',
    description: 'curl with environment variable in header',
  },
  {
    name: 'wget_post_env',
    pattern: /wget\s+.*--post-data.*\$\{?[A-Z_]/i,
    severity: 'critical',
    description: 'wget POST with environment variable',
  },
];

export const CRYPTO_MINING_PATTERNS: BlockPattern[] = [
  {
    name: 'xmrig',
    pattern: /xmrig/i,
    severity: 'critical',
    description: 'XMRig cryptocurrency miner',
  },
  {
    name: 'minerd',
    pattern: /minerd/i,
    severity: 'critical',
    description: 'Minerd cryptocurrency miner',
  },
  {
    name: 'cgminer',
    pattern: /cgminer/i,
    severity: 'critical',
    description: 'CGMiner cryptocurrency miner',
  },
  {
    name: 'bfgminer',
    pattern: /bfgminer/i,
    severity: 'critical',
    description: 'BFGMiner cryptocurrency miner',
  },
  {
    name: 'stratum_protocol',
    pattern: /stratum\+tcp/i,
    severity: 'critical',
    description: 'Stratum mining protocol',
  },
];

export const OBFUSCATED_EXEC_PATTERNS: BlockPattern[] = [
  {
    name: 'base64_pipe_bash',
    pattern: /\|\s*base64\s+-d\s*\|\s*(ba)?sh/i,
    severity: 'critical',
    description: 'Base64 decode piped to shell',
  },
  {
    name: 'base64_decode_bash',
    pattern: /base64\s+(-d|--decode)\s+\S+\s*\|\s*(ba)?sh/i,
    severity: 'critical',
    description: 'Base64 decode from file piped to shell',
  },
  {
    name: 'eval_base64_decode',
    pattern: /eval\s*\(\s*base64_decode/i,
    severity: 'critical',
    description: 'PHP-style eval with base64 decode',
  },
];

// All instant block patterns combined
export const INSTANT_BLOCK_PATTERNS: BlockPattern[] = [
  ...REVERSE_SHELL_PATTERNS,
  ...DATA_EXFIL_PATTERNS,
  ...CRYPTO_MINING_PATTERNS,
  ...OBFUSCATED_EXEC_PATTERNS,
];

// =============================================================================
// Checkpoint Patterns - Trigger security review
// =============================================================================

export interface CheckpointPattern {
  pattern: RegExp;
  type: 'network' | 'package_install' | 'git_operation' | 'file_sensitive' | 'script_execution' | 'env_modification';
  description: string;
}

export const CHECKPOINT_PATTERNS: CheckpointPattern[] = [
  // Script execution
  { pattern: /curl\s+.*\|\s*(ba)?sh/i, type: 'script_execution', description: 'curl piped to shell' },
  { pattern: /wget\s+.*\|\s*(ba)?sh/i, type: 'script_execution', description: 'wget piped to shell' },
  { pattern: /curl\s+.*-o\s*-\s*\|/i, type: 'script_execution', description: 'curl output piped' },
  { pattern: /chmod\s+\+x/i, type: 'script_execution', description: 'Making file executable' },
  { pattern: /\.\/[^\s]+\.sh/i, type: 'script_execution', description: 'Running shell script' },
  { pattern: /bash\s+[^\s]+\.sh/i, type: 'script_execution', description: 'Running shell script with bash' },

  // Network operations
  { pattern: /curl\s+.*?(https?:\/\/[^\s"']+)/i, type: 'network', description: 'curl HTTP request' },
  { pattern: /wget\s+.*?(https?:\/\/[^\s"']+)/i, type: 'network', description: 'wget HTTP request' },

  // Package installations
  { pattern: /npm\s+install\s+(?!-[dDgG])/i, type: 'package_install', description: 'npm install' },
  { pattern: /pnpm\s+(add|install)/i, type: 'package_install', description: 'pnpm add/install' },
  { pattern: /yarn\s+add/i, type: 'package_install', description: 'yarn add' },
  { pattern: /pip\s+install/i, type: 'package_install', description: 'pip install' },
  { pattern: /apt(-get)?\s+install/i, type: 'package_install', description: 'apt install' },
  { pattern: /brew\s+install/i, type: 'package_install', description: 'brew install' },

  // Git operations
  { pattern: /git\s+push/i, type: 'git_operation', description: 'git push' },
  { pattern: /git\s+commit/i, type: 'git_operation', description: 'git commit' },
  { pattern: /git\s+reset\s+--hard/i, type: 'git_operation', description: 'git reset --hard' },
  { pattern: /git\s+.*--force/i, type: 'git_operation', description: 'git force operation' },

  // Environment files
  { pattern: /\.env(?:\.local|\.production|\.development)?(?:\s|$|["'])/i, type: 'env_modification', description: '.env file access' },

  // Sensitive files
  { pattern: /\.ssh/i, type: 'file_sensitive', description: 'SSH directory access' },
  { pattern: /\.aws/i, type: 'file_sensitive', description: 'AWS credentials access' },
  { pattern: /credentials/i, type: 'file_sensitive', description: 'Credentials file access' },
  { pattern: /CLAUDE\.md/i, type: 'file_sensitive', description: 'CLAUDE.md modification' },
];
