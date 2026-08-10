import assert from 'node:assert/strict';
import test from 'node:test';

import { isLocalSftpPath, sshMaxSftpPathLength } from '../electron/sftp-contract.ts';

test('local SFTP paths accept native POSIX roots on Linux and macOS', () => {
  for (const platform of ['linux', 'darwin'] as const) {
    assert.equal(isLocalSftpPath('/', false, platform), true);
    assert.equal(isLocalSftpPath('/home/operator', false, platform), true);
    assert.equal(isLocalSftpPath('/Users/operator', false, platform), true);
    assert.equal(isLocalSftpPath('relative/path', false, platform), false);
    assert.equal(isLocalSftpPath('C:\\Users\\operator', false, platform), false);
  }
});

test('local SFTP paths preserve Windows drive and UNC validation', () => {
  assert.equal(isLocalSftpPath('C:\\Users\\operator', false, 'win32'), true);
  assert.equal(isLocalSftpPath('C:/Users/operator', false, 'win32'), true);
  assert.equal(isLocalSftpPath('\\\\server\\share', false, 'win32'), true);
  assert.equal(isLocalSftpPath('/home/operator', false, 'win32'), false);
  assert.equal(isLocalSftpPath('relative\\path', false, 'win32'), false);
});

test('local SFTP paths allow only the explicit empty home request', () => {
  for (const platform of ['linux', 'darwin', 'win32'] as const) {
    assert.equal(isLocalSftpPath('', true, platform), true);
    assert.equal(isLocalSftpPath('', false, platform), false);
  }
  assert.equal(isLocalSftpPath('/home/operator\u0000/file', false, 'linux'), false);
  assert.equal(isLocalSftpPath('C:\\Users\\operator\u0000file', false, 'win32'), false);
});

test('local SFTP path limits are measured in UTF-8 bytes on every platform', () => {
  const maxPosixPath = `/${'a'.repeat(sshMaxSftpPathLength - 1)}`;
  const maxWindowsPath = `C:\\${'a'.repeat(sshMaxSftpPathLength - 3)}`;
  assert.equal(isLocalSftpPath(maxPosixPath, false, 'linux'), true);
  assert.equal(isLocalSftpPath(`${maxPosixPath}a`, false, 'linux'), false);
  assert.equal(isLocalSftpPath(maxWindowsPath, false, 'win32'), true);
  assert.equal(isLocalSftpPath(`${maxWindowsPath}a`, false, 'win32'), false);
  assert.equal(isLocalSftpPath(`/${'é'.repeat(sshMaxSftpPathLength / 2)}`, false, 'linux'), false);
});
