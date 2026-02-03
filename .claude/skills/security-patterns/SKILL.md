---
name: security-patterns
description: VibeSafe 보안 패턴 정의 및 업데이트 가이드라인.
---

# Instant Block Patterns

## Reverse Shell

```typescript
const REVERSE_SHELL_PATTERNS = [
  /bash\s+-i\s+>&\s+\/dev\/tcp/i,
  /nc\s+-e\s+\/bin\/(ba)?sh/i,
  /python[23]?\s+-c\s+['"]import\s+socket/i,
  /perl\s+-e\s+['"]use\s+Socket/i,
];
```

## Data Exfiltration

```typescript
const DATA_EXFIL_PATTERNS = [
  /curl.*\$\{?[A-Z_]*KEY/i,           // curl with API key
  /curl.*\$\{?[A-Z_]*TOKEN/i,         // curl with token
  /wget.*\$\{?[A-Z_]*SECRET/i,        // wget with secret
  /curl\s+.*--data.*\$\{?[A-Z_]/i,    // POST with env var
];
```

## Crypto Mining

```typescript
const CRYPTO_MINING_PATTERNS = [
  /xmrig/i,
  /minerd/i,
  /cpuminer/i,
  /stratum\+tcp/i,
];
```

## Pattern Update Rules

1. 새 패턴 추가 전 테스트 케이스 작성
2. False positive 검증 (정상 명령이 차단되지 않는지)
3. 성능 테스트 (정규표현식 복잡도)
4. 문서화 (왜 이 패턴이 필요한지)

# Trusted Domains

```typescript
const TRUSTED_DOMAINS = [
  'github.com',
  'raw.githubusercontent.com',
  'bun.sh',
  'deno.land',
  'nodejs.org',
  'npmjs.com',
  'registry.npmjs.org',
  'get.docker.com',
  'brew.sh',
  'rustup.rs',
  'pypa.io',
  'pypi.org',
];
```
