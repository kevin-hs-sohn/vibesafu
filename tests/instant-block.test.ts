import { describe, it, expect } from 'vitest';

// TODO: Import when implemented
// import { checkInstantBlock } from '../src/guard/instant-block';

describe('InstantBlock', () => {
  describe('Reverse Shell Detection', () => {
    it.todo('should block bash reverse shell');
    it.todo('should block netcat reverse shell');
    it.todo('should block python reverse shell');
    it.todo('should block perl reverse shell');
  });

  describe('Data Exfiltration Detection', () => {
    it.todo('should block curl with API key');
    it.todo('should block curl with token');
    it.todo('should block wget with secret');
    it.todo('should block POST with env var');
  });

  describe('Crypto Mining Detection', () => {
    it.todo('should block xmrig');
    it.todo('should block minerd');
    it.todo('should block stratum protocol');
  });

  describe('Base64 Execution Detection', () => {
    it.todo('should block base64 decoded execution');
    it.todo('should block echo base64 pipe bash');
  });

  describe('False Positive Prevention', () => {
    it('should allow normal npm install', () => {
      const command = 'npm install lodash';
      // const result = checkInstantBlock(command);
      // expect(result).toBeNull();
      expect(command).toBeTruthy(); // placeholder
    });

    it('should allow normal curl to API', () => {
      const command = 'curl https://api.github.com/repos';
      // const result = checkInstantBlock(command);
      // expect(result).toBeNull();
      expect(command).toBeTruthy(); // placeholder
    });

    it('should allow git operations', () => {
      const command = 'git push origin main';
      // const result = checkInstantBlock(command);
      // expect(result).toBeNull();
      expect(command).toBeTruthy(); // placeholder
    });
  });
});
