/**
 * Checkpoint Detection - Identify commands that need security review
 */

import { CHECKPOINT_PATTERNS } from '../config/patterns.js';

export interface SecurityCheckpoint {
  type: 'network' | 'package_install' | 'git_operation' | 'file_sensitive' | 'script_execution' | 'env_modification';
  command: string;
  description: string;
}

/**
 * Detect if a command triggers a security checkpoint
 * Returns the checkpoint info if triggered, null otherwise
 */
export function detectCheckpoint(command: string): SecurityCheckpoint | null {
  // Empty or whitespace-only commands don't trigger checkpoints
  if (!command || !command.trim()) {
    return null;
  }

  for (const { pattern, type, description } of CHECKPOINT_PATTERNS) {
    if (pattern.test(command)) {
      return {
        type,
        command,
        description,
      };
    }
  }

  return null;
}
