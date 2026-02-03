/**
 * Instant Block - Immediately block known dangerous patterns
 * No LLM call needed for these obvious threats
 */

import { INSTANT_BLOCK_PATTERNS } from '../config/patterns.js';

export interface InstantBlockResult {
  blocked: boolean;
  reason?: string;
  patternName?: string;
  severity?: 'critical' | 'high' | 'medium';
}

/**
 * Check if a command matches any instant block pattern
 * Returns immediately without any LLM call
 */
export function checkInstantBlock(command: string): InstantBlockResult {
  // Empty or whitespace-only commands are safe
  if (!command || !command.trim()) {
    return { blocked: false };
  }

  for (const pattern of INSTANT_BLOCK_PATTERNS) {
    if (pattern.pattern.test(command)) {
      return {
        blocked: true,
        reason: `Blocked: Matches dangerous pattern - ${pattern.description}`,
        patternName: pattern.name,
        severity: pattern.severity,
      };
    }
  }

  return { blocked: false };
}
