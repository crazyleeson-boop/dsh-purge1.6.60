import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { looksLikeDesktopName, looksLikeDesktopNameTail, isDesktopExecutable, clearDesktopLocateCache } from '../lib/desktop.js';
import { clearDesktopIdentityCache } from '../lib/desktop-identity.js';

function tmp(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'purge desktop-next '));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  clearDesktopIdentityCache(); clearDesktopLocateCache();
  return root;
}

test('dsh next family is a desktop name, matching the original project list', () => {
  for (const p of ['E:\\DSH NEXT\\resources', 'E:\\DSH NEXT\\DSH NEXT.exe', '/Apps/DSH NEXT.app/Contents/MacOS',
    'C:\\apps\\dsh-desktop-next', 'C:\\apps\\dsh-next', '/opt/dsh desktop/bin']) {
    assert.equal(looksLikeDesktopName(p), true, p);
  }
  for (const p of ['C:\\Users\\x\\.dsh\\profiles\\desktop', 'C:\\Program Files\\nodejs\\node.exe', '']) {
    assert.equal(looksLikeDesktopName(p), false, p);
  }
});

test('desktop name tail accepts bare executable names from the original project', () => {
  for (const p of ['E:\\DSH NEXT\\DSH NEXT.exe', 'DSH NEXT', 'dsh next.exe', 'dsh desktop.exe',
    'dsh-desktop-next.exe', 'DeepSeek Bot.exe', 'ds-bot.exe']) {
    assert.equal(looksLikeDesktopNameTail(p), true, p);
  }
  for (const p of ['E:\\DSH NEXT\\resources', 'D:\\DeepSeek Harness\\npm-global', 'foo.exe', 'desktop']) {
    assert.equal(looksLikeDesktopNameTail(p), false, p);
  }
});

test('isDesktopExecutable falls back to the file name before the archive is unpacked', t => {
  const root = tmp(t);
  for (const name of ['DSH NEXT.exe', 'DSH Desktop.exe', 'dsh-desktop-next.exe']) {
    const exe = path.join(root, name);
    fs.writeFileSync(exe, '');
    assert.equal(isDesktopExecutable(exe), true, name);
  }
  const other = path.join(root, 'foo.exe');
  fs.writeFileSync(other, '');
  assert.equal(isDesktopExecutable(other), false);
  assert.equal(isDesktopExecutable(''), false);
  assert.equal(isDesktopExecutable(path.join(root, 'missing.exe')), false);
});

test('archive evidence still wins and missing resources never throws', t => {
  const root = tmp(t);
  const exe = path.join(root, 'DSH NEXT.exe');
  fs.writeFileSync(exe, '');
  const resources = path.join(root, 'resources');
  fs.mkdirSync(path.join(resources, 'app', 'node_modules', '@deepseek-ai', 'dsh-agent-instructions', 'lib'), { recursive: true });
  fs.writeFileSync(path.join(resources, 'app', 'package.json'), JSON.stringify({ name: 'dsh-desktop-next', main: 'lib/main.js' }));
  fs.mkdirSync(path.join(resources, 'app', 'lib'), { recursive: true });
  fs.writeFileSync(path.join(resources, 'app', 'lib', 'main.js'), '// fixture');
  assert.equal(isDesktopExecutable(exe), true);
  assert.doesNotThrow(() => isDesktopExecutable(path.join(root, 'nope', 'DSH NEXT.exe')));
});
