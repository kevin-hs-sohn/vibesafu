#!/usr/bin/env node

/**
 * VibeSafe CLI - Claude Code Security Guard
 *
 * Commands:
 *   install   - Install hook to ~/.claude/settings.json
 *   uninstall - Remove hook from settings
 *   check     - Run security check (stdin: PermissionRequest JSON)
 *   config    - Configure API key and settings
 */

import { parseArgs } from 'node:util';

const COMMANDS = ['install', 'uninstall', 'check', 'config'] as const;
type Command = (typeof COMMANDS)[number];

async function main(): Promise<void> {
  const { positionals } = parseArgs({
    allowPositionals: true,
    strict: false,
  });

  const command = positionals[0] as Command | undefined;

  if (!command || !COMMANDS.includes(command)) {
    console.error(`Usage: vibesafe <${COMMANDS.join('|')}>`);
    console.error('');
    console.error('Commands:');
    console.error('  install   - Install security hook to Claude Code');
    console.error('  uninstall - Remove security hook');
    console.error('  check     - Run security check (stdin: PermissionRequest JSON)');
    console.error('  config    - Configure API key and settings');
    process.exit(1);
  }

  // TODO: Implement command handlers
  switch (command) {
    case 'install':
      console.log('TODO: Install hook');
      break;
    case 'uninstall':
      console.log('TODO: Uninstall hook');
      break;
    case 'check':
      console.log('TODO: Run security check');
      break;
    case 'config':
      console.log('TODO: Configure settings');
      break;
  }
}

main().catch((error: Error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
