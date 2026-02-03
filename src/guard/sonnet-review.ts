/**
 * Sonnet Review - Deep security analysis
 *
 * Uses Claude Sonnet for thorough security review of escalated cases.
 * Returns: ALLOW | ASK_USER | BLOCK
 */

import type Anthropic from '@anthropic-ai/sdk';
import type { SecurityCheckpoint } from '../types.js';
import type { TriageResult } from './haiku-triage.js';

export type ReviewVerdict = 'ALLOW' | 'ASK_USER' | 'BLOCK';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface ReviewResult {
  verdict: ReviewVerdict;
  riskLevel: RiskLevel;
  reason: string;
  userMessage?: string;
}

const SONNET_MODEL = 'claude-sonnet-4-20250514';

const REVIEW_PROMPT = `You are a senior security engineer reviewing a potentially risky operation.

## Operation Details
Command: {command}
Checkpoint Type: {checkpoint_type}
Context: {context}

## Initial Triage
Reason: {triage_reason}
Risk Indicators: {risk_indicators}

## Your Analysis

Analyze this operation for security risks:

1. **Intent Analysis**: What is this command trying to accomplish?
2. **Risk Assessment**: What could go wrong?
3. **Mitigation**: Are there safer alternatives?

## Verdict

ALLOW - Safe to proceed autonomously
- Legitimate development operation
- No significant risk to system or data
- Source is verifiable and trusted

ASK_USER - Need human approval
- Operation has potential risks but may be legitimate
- User should understand what will happen
- Provide clear explanation of risks

BLOCK - Do not allow
- Clear security risk
- No legitimate use case in this context
- Could cause data loss or system compromise

## Response Format (JSON only)
{
  "verdict": "ALLOW" | "ASK_USER" | "BLOCK",
  "risk_level": "low" | "medium" | "high" | "critical",
  "analysis": {
    "intent": "What the command does",
    "risks": ["Risk 1", "Risk 2"],
    "mitigations": ["Alternative 1", "Alternative 2"]
  },
  "user_message": "Message to show the user if ASK_USER (null if not applicable)"
}`;

/**
 * Perform deep security review using Sonnet
 */
export async function reviewWithSonnet(
  client: Anthropic,
  checkpoint: SecurityCheckpoint,
  triage: TriageResult
): Promise<ReviewResult> {
  const prompt = REVIEW_PROMPT
    .replace('{command}', checkpoint.command)
    .replace('{checkpoint_type}', checkpoint.type)
    .replace('{context}', checkpoint.description)
    .replace('{triage_reason}', triage.reason)
    .replace('{risk_indicators}', triage.riskIndicators.join(', ') || 'none');

  try {
    const response = await client.messages.create({
      model: SONNET_MODEL,
      max_tokens: 1000,
      messages: [{ role: 'user', content: prompt }],
    });

    const text = response.content[0]?.type === 'text' ? response.content[0].text : '';

    if (!text) {
      return {
        verdict: 'ASK_USER',
        riskLevel: 'medium',
        reason: 'Review failed: Empty response from Sonnet',
        userMessage: 'Automated security review failed. Please review this operation manually.',
      };
    }

    // Extract JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return {
        verdict: 'ASK_USER',
        riskLevel: 'medium',
        reason: 'Review failed: Could not parse JSON response',
        userMessage: 'Automated security review failed. Please review this operation manually.',
      };
    }

    const parsed = JSON.parse(jsonMatch[0]) as {
      verdict?: ReviewVerdict;
      risk_level?: RiskLevel;
      analysis?: {
        intent?: string;
        risks?: string[];
        mitigations?: string[];
      };
      user_message?: string | null;
    };

    // Validate verdict
    const verdict = parsed.verdict ?? 'ASK_USER';
    if (!['ALLOW', 'ASK_USER', 'BLOCK'].includes(verdict)) {
      return {
        verdict: 'ASK_USER',
        riskLevel: 'medium',
        reason: 'Review failed: Invalid verdict in response',
        userMessage: 'Automated security review failed. Please review this operation manually.',
      };
    }

    const result: ReviewResult = {
      verdict,
      riskLevel: parsed.risk_level ?? 'medium',
      reason: parsed.analysis?.intent ?? 'Review completed',
    };

    if (parsed.user_message) {
      result.userMessage = parsed.user_message;
    }

    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return {
      verdict: 'ASK_USER',
      riskLevel: 'medium',
      reason: `Review failed: ${errorMessage}`,
      userMessage: 'Automated security review failed. Please review this operation manually.',
    };
  }
}
