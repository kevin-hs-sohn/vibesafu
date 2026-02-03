/**
 * Input sanitization utilities for LLM prompt injection defense
 */

/**
 * Maximum allowed command length for LLM analysis
 */
export const MAX_COMMAND_LENGTH = 2000;

/**
 * Patterns that indicate potential prompt injection attempts
 */
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous\s+)?instructions/i,
  /forget\s+(all\s+)?(previous\s+)?instructions/i,
  /disregard\s+(all\s+)?(previous\s+)?instructions/i,
  /you\s+are\s+(now\s+)?a/i,
  /new\s+instructions?:/i,
  /system\s*:/i,
  /assistant\s*:/i,
  /human\s*:/i,
  /\bIMPORTANT\s*:/i,
  /\bNOTE\s*:/i,
  /respond\s+with\s+(this\s+)?(exact\s+)?json/i,
  /for\s+testing\s+purposes/i,
  /end\s+of\s+(test\s+)?instructions/i,
];

/**
 * Check if command contains prompt injection patterns
 */
export function containsPromptInjection(command: string): boolean {
  return PROMPT_INJECTION_PATTERNS.some((pattern) => pattern.test(command));
}

/**
 * Sanitize command for safe inclusion in LLM prompts
 * - Truncates to max length
 * - Escapes special characters that could break prompt structure
 * - Normalizes whitespace
 */
export function sanitizeForPrompt(command: string): string {
  let sanitized = command;

  // Truncate to max length
  if (sanitized.length > MAX_COMMAND_LENGTH) {
    sanitized = sanitized.slice(0, MAX_COMMAND_LENGTH) + '... [truncated]';
  }

  // Replace characters that could break XML-like structure
  sanitized = sanitized
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Normalize excessive newlines (potential injection delimiter)
  sanitized = sanitized.replace(/\n{3,}/g, '\n\n');

  return sanitized;
}

/**
 * Escape string for XML content
 */
export function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Risk indicators that should force escalation even if LLM says SELF_HANDLE
 */
const FORCE_ESCALATE_PATTERNS = [
  /\|\s*(ba)?sh/i,                    // Pipe to shell
  /curl.*\|/i,                        // curl piped to something
  /wget.*\|/i,                        // wget piped to something
  /base64/i,                          // Base64 operations
  /eval\s*\(/i,                       // eval() calls
  /\$\([^)]+\)/,                      // Command substitution
  /`[^`]+`/,                          // Backtick command substitution
  />\s*\/dev\/tcp/i,                  // /dev/tcp redirection
  /nc\s+.*-[elp]/i,                   // netcat with execution/listen flags
  /\bsudo\b/i,                        // sudo commands
  /\bsu\b\s+-/i,                      // su commands
  /chmod\s+[0-7]*[7][0-7]*/i,         // chmod with executable permissions
  /\.env/i,                           // env file access
  /\/(etc|root|home)\//i,             // System directory access
];

/**
 * Check if command should force escalation regardless of LLM response
 * This is a safety net against prompt injection attacks
 */
export function shouldForceEscalate(command: string): boolean {
  // Check for prompt injection attempts
  if (containsPromptInjection(command)) {
    return true;
  }

  // Check for risky patterns that shouldn't be auto-approved
  return FORCE_ESCALATE_PATTERNS.some((pattern) => pattern.test(command));
}
