import assert from 'node:assert/strict';
import test from 'node:test';

import { formatSftpDate, formatSftpSize } from '../src/sftp-format.ts';

test('SFTP size formatting matches the WinUI byte-size converter', () => {
  assert.equal(formatSftpSize(0), '');
  assert.equal(formatSftpSize(512), '512 B');
  assert.equal(formatSftpSize(1024), '1 KB');
  assert.equal(formatSftpSize(10.25 * 1024 * 1024), '10.3 MB');
  assert.equal(formatSftpSize(2 * 1024 * 1024 * 1024), '2 GB');
});

test('SFTP date formatting uses local WinUI-style minute precision', () => {
  const date = new Date(2026, 7, 5, 14, 7, 32);
  assert.equal(formatSftpDate(date.toISOString()), '2026-08-05 14:07');
  assert.equal(formatSftpDate('not-a-date'), '');
  assert.equal(formatSftpDate(), '');
});
