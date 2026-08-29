/**
 * Server-side OTP filter — the second, independent layer.
 *
 * The sender filters before transmission; this exists so a stale, modified, or
 * impersonated sender still cannot get an authentication code into the archive.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { checkOtp } from '../src/shared/otp-filter.js';

const filtered = (text: string, over: Record<string, unknown> = {}): boolean =>
  checkOtp({ text, isFromMe: false, senderHandle: '+15550009999', counterpartHandles: ['+15550009999'], ...over }, { filterShortcodeSenders: false }).filtered;

test('classic verification-code phrasings are filtered', () => {
  const samples = [
    'Your verification code is 123456',
    'Your security code is 8842. Do not share this code with anyone.',
    '482913 is your login code',
    'Use authentication code 55210 to sign in',
    'Your one-time password: 99182',
    'Your OTP is 123 456',
    'Your 2FA code is 771122',
    'MFA code: 665544',
    'Your temporary passcode is 4821',
    'G-882931 is your Google verification code',
    'Do not share this code with anyone: 771213',
    'Enter 991823 to verify your phone number',
    'Your Apple ID code is: 123456. Do not share it with anyone.',
    'Your confirmation code is 44219',
  ];
  for (const s of samples) {
    assert.ok(filtered(s), `NOT filtered but should be: ${s}`);
  }
});

test('ordinary conversation is not filtered', () => {
  const samples = [
    'Hey, are we still on for Yosemite next weekend?',
    'The code review is done, I left two comments',
    'My flight is AA 1234, landing at 6:15',
    'Apartment code is on the fridge, see you soon',
    'I got 95210 on that level, finally',
    'Call me back when you can',
    'The security deposit is 1500, due Friday',
    'Can you send me the recipe for those one-pot pastas',
  ];
  for (const s of samples) {
    assert.ok(!filtered(s), `wrongly filtered: ${s}`);
  }
});

test('outbound messages are filtered on content too', () => {
  // The shared filter only uses isFromMe to suppress the shortcode-sender
  // heuristic; content patterns still apply in both directions. That is
  // deliberate — a code I forwarded to someone is still a code, and erring
  // toward dropping it is the correct bias for this archive.
  const verdict = checkOtp({
    text: 'my verification code was 123456 if that helps',
    isFromMe: true,
    counterpartHandles: ['+15550001111'],
  });
  assert.equal(verdict.filtered, true);

  // Ordinary outbound conversation is untouched.
  assert.equal(
    checkOtp({ text: 'heading out now, see you at 7', isFromMe: true, counterpartHandles: ['+15550001111'] }).filtered,
    false,
  );
});

test('shortcode-sender filtering is opt-in on the server', () => {
  const msg = { text: 'Your package was delivered', isFromMe: false, senderHandle: '22000', counterpartHandles: ['22000'] };
  // Server default (what the ingestion service passes): content patterns only,
  // so a legitimate automated message the Mac chose to send is archived.
  assert.equal(checkOtp(msg, { filterShortcodeSenders: false }).filtered, false);
  // Opt in and the whole sender class is dropped — this is the sender's default.
  assert.equal(checkOtp(msg, { filterShortcodeSenders: true }).filtered, true);
  // Either way, an actual code from that sender is filtered.
  assert.equal(
    checkOtp({ ...msg, text: 'Your verification code is 448122' }, { filterShortcodeSenders: false }).filtered,
    true,
  );
});

test('the verdict never echoes the message text', () => {
  const secret = 'Your verification code is 918273';
  const verdict = checkOtp({ text: secret, isFromMe: false, senderHandle: '22000', counterpartHandles: ['22000'] });
  assert.ok(verdict.filtered);
  const serialized = JSON.stringify(verdict);
  assert.ok(!serialized.includes('918273'), 'the code leaked into the verdict object');
  assert.ok(!serialized.includes(secret), 'the message text leaked into the verdict object');
});

test('an empty or absent body is not filtered', () => {
  assert.equal(checkOtp({ text: undefined, isFromMe: false, counterpartHandles: [] }).filtered, false);
  assert.equal(checkOtp({ text: '', isFromMe: false, counterpartHandles: [] }).filtered, false);
});
