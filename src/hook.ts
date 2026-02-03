/**
 * VibeSafe Hook Handler
 * Main entry point for processing PermissionRequest events
 */

import Anthropic from '@anthropic-ai/sdk';
import type {
  PermissionRequestInput,
  PermissionRequestOutput,
  SecurityCheckpoint,
} from './types.js';
import { checkInstantBlock } from './guard/instant-block.js';
import { detectCheckpoint } from './guard/checkpoint.js';
import { checkTrustedDomains } from './guard/trusted-domain.js';
import { triageWithHaiku } from './guard/haiku-triage.js';
import { reviewWithSonnet } from './guard/sonnet-review.js';
import { getApiKey } from './cli/config.js';

export type HookDecision = 'allow' | 'deny' | 'needs-review';
export type DecisionSource =
  | 'instant-block'
  | 'trusted-domain'
  | 'no-checkpoint'
  | 'checkpoint'
  | 'non-bash-tool'
  | 'haiku'
  | 'sonnet';

export interface ProcessResult {
  decision: HookDecision;
  reason: string;
  source: DecisionSource;
  checkpoint?: SecurityCheckpoint;
  userMessage?: string;
}

/**
 * Process a PermissionRequest and determine if it should be allowed
 *
 * Flow:
 * 1. Non-Bash tools → Allow (only analyze Bash commands)
 * 2. Instant Block → Deny immediately
 * 3. No Checkpoint → Allow (safe command)
 * 4. Trusted Domain → Allow (script from trusted source)
 * 5. Checkpoint Triggered → LLM review (Haiku → Sonnet if escalated)
 */
export async function processPermissionRequest(
  input: PermissionRequestInput,
  anthropicClient?: Anthropic
): Promise<ProcessResult> {
  // Step 1: Only analyze Bash commands
  if (input.tool_name !== 'Bash') {
    return {
      decision: 'allow',
      reason: `Tool ${input.tool_name} is not Bash, allowing`,
      source: 'non-bash-tool',
    };
  }

  const command = input.tool_input.command as string;

  // Step 2: Check for instant block patterns
  const blockResult = checkInstantBlock(command);
  if (blockResult.blocked) {
    return {
      decision: 'deny',
      reason: blockResult.reason ?? 'Blocked by instant block',
      source: 'instant-block',
    };
  }

  // Step 3: Check if command triggers a checkpoint
  const checkpoint = detectCheckpoint(command);
  if (!checkpoint) {
    return {
      decision: 'allow',
      reason: 'No security checkpoint triggered',
      source: 'no-checkpoint',
    };
  }

  // Step 4: For script execution or network, check trusted domains
  if (checkpoint.type === 'script_execution' || checkpoint.type === 'network') {
    const domainResult = checkTrustedDomains(command);
    if (domainResult.allTrusted && domainResult.urls.length > 0) {
      return {
        decision: 'allow',
        reason: `All URLs from trusted domains: ${domainResult.trustedUrls.join(', ')}`,
        source: 'trusted-domain',
      };
    }
  }

  // Step 5: LLM review if API key is available
  if (!anthropicClient) {
    return {
      decision: 'needs-review',
      reason: `Checkpoint triggered: ${checkpoint.type} - ${checkpoint.description}`,
      source: 'checkpoint',
      checkpoint,
    };
  }

  // Step 5a: Haiku triage
  const triage = await triageWithHaiku(anthropicClient, checkpoint);

  if (triage.classification === 'BLOCK') {
    return {
      decision: 'deny',
      reason: `Blocked by Haiku: ${triage.reason}`,
      source: 'haiku',
    };
  }

  if (triage.classification === 'SELF_HANDLE') {
    return {
      decision: 'allow',
      reason: `Approved by Haiku: ${triage.reason}`,
      source: 'haiku',
    };
  }

  // Step 5b: Escalate to Sonnet for deeper review
  const review = await reviewWithSonnet(anthropicClient, checkpoint, triage);

  if (review.verdict === 'BLOCK') {
    return {
      decision: 'deny',
      reason: `Blocked by Sonnet: ${review.reason}`,
      source: 'sonnet',
    };
  }

  if (review.verdict === 'ALLOW') {
    return {
      decision: 'allow',
      reason: `Approved by Sonnet: ${review.reason}`,
      source: 'sonnet',
    };
  }

  // ASK_USER - return as needs-review with user message
  const result: ProcessResult = {
    decision: 'needs-review',
    reason: review.reason,
    source: 'sonnet',
    checkpoint,
  };
  if (review.userMessage) {
    result.userMessage = review.userMessage;
  }
  return result;
}

/**
 * Create the hook output in the expected format
 */
export function createHookOutput(
  decision: 'allow' | 'deny',
  message?: string
): PermissionRequestOutput {
  const output: PermissionRequestOutput = {
    hookSpecificOutput: {
      hookEventName: 'PermissionRequest',
      decision: {
        behavior: decision,
      },
    },
  };

  if (message !== undefined) {
    output.hookSpecificOutput.decision.message = message;
  }

  return output;
}

/**
 * Main hook handler - reads from stdin, writes to stdout
 */
export async function runHook(): Promise<void> {
  // Read input from stdin
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const inputJson = Buffer.concat(chunks).toString('utf-8');

  let input: PermissionRequestInput;
  try {
    input = JSON.parse(inputJson) as PermissionRequestInput;
  } catch {
    // Invalid JSON, deny for safety
    const output = createHookOutput('deny', 'Invalid JSON input');
    console.log(JSON.stringify(output));
    return;
  }

  // Try to get API key and create Anthropic client
  let anthropicClient: Anthropic | undefined;
  const apiKey = await getApiKey();
  if (apiKey) {
    anthropicClient = new Anthropic({ apiKey });
  }

  // Process the request
  const result = await processPermissionRequest(input, anthropicClient);

  // Convert result to hook output
  let output: PermissionRequestOutput;

  if (result.decision === 'deny') {
    output = createHookOutput('deny', result.reason);
  } else if (result.decision === 'needs-review') {
    if (result.userMessage) {
      // Sonnet asked for user confirmation
      output = createHookOutput('deny', `User approval required: ${result.userMessage}`);
    } else {
      // No API key configured
      output = createHookOutput(
        'deny',
        `Security review required: ${result.reason}. Configure API key with 'vibesafe config' to enable LLM analysis.`
      );
    }
  } else {
    output = createHookOutput('allow');
  }

  console.log(JSON.stringify(output));
}
