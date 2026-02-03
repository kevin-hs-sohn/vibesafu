/**
 * Haiku Triage - Fast first-pass classification
 *
 * Uses Claude Haiku for quick, cost-effective security triage.
 * Returns: SELF_HANDLE | ESCALATE | BLOCK
 */

import type Anthropic from '@anthropic-ai/sdk';
import type { SecurityCheckpoint } from '../types.js';

export type TriageClassification = 'SELF_HANDLE' | 'ESCALATE' | 'BLOCK';

export interface TriageResult {
  classification: TriageClassification;
  reason: string;
  riskIndicators: string[];
}

const HAIKU_MODEL = 'claude-haiku-4-20250514';

const TRIAGE_PROMPT = `You are a security triage agent for an autonomous coding system.

## Your job
Quickly classify this security checkpoint.

## Command
{command}

## Checkpoint Type
{checkpoint_type}

## Context
{context}

## Classification Rules

SELF_HANDLE - You can approve this yourself:
- Downloads from known trusted domains (github.com, npmjs.com, bun.sh, docker.com, etc.)
- Standard package manager operations (npm install <well-known-package>)
- Git commits with reasonable messages
- File operations within the project directory
- Reading (not writing) config files

ESCALATE - Needs deeper analysis by a smarter model:
- Downloaded scripts that need code review
- Unfamiliar packages or sources
- Commands with complex piping
- System-level operations
- Multiple chained commands with side effects
- Anything that modifies .env or credentials

BLOCK - Obviously dangerous, block immediately:
- rm -rf on paths outside project
- Sending secrets/env vars to external URLs
- Reverse shell patterns
- Cryptocurrency mining
- Base64 encoded execution

## Response Format (JSON only)
{
  "classification": "SELF_HANDLE" | "ESCALATE" | "BLOCK",
  "reason": "Brief explanation",
  "risk_indicators": ["list", "of", "concerns"]
}`;

/**
 * Perform fast triage using Haiku
 */
export async function triageWithHaiku(
  client: Anthropic,
  checkpoint: SecurityCheckpoint
): Promise<TriageResult> {
  const prompt = TRIAGE_PROMPT
    .replace('{command}', checkpoint.command)
    .replace('{checkpoint_type}', checkpoint.type)
    .replace('{context}', checkpoint.description);

  try {
    const response = await client.messages.create({
      model: HAIKU_MODEL,
      max_tokens: 500,
      messages: [{ role: 'user', content: prompt }],
    });

    const text = response.content[0]?.type === 'text' ? response.content[0].text : '';

    if (!text) {
      return {
        classification: 'ESCALATE',
        reason: 'Triage failed: Empty response from Haiku',
        riskIndicators: ['triage_error'],
      };
    }

    // Extract JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return {
        classification: 'ESCALATE',
        reason: 'Triage failed: Could not parse JSON response',
        riskIndicators: ['triage_error'],
      };
    }

    const parsed = JSON.parse(jsonMatch[0]) as {
      classification?: TriageClassification;
      reason?: string;
      risk_indicators?: string[];
    };

    // Validate classification
    if (!parsed.classification || !['SELF_HANDLE', 'ESCALATE', 'BLOCK'].includes(parsed.classification)) {
      return {
        classification: 'ESCALATE',
        reason: 'Triage failed: Invalid classification in response',
        riskIndicators: ['triage_error'],
      };
    }

    return {
      classification: parsed.classification,
      reason: parsed.reason ?? 'No reason provided',
      riskIndicators: parsed.risk_indicators ?? [],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return {
      classification: 'ESCALATE',
      reason: `Triage failed: ${errorMessage}`,
      riskIndicators: ['triage_error'],
    };
  }
}
