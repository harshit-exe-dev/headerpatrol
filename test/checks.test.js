import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkHsts, checkCsp, checkCookies, checkCors, checkFrameProtection } from '../src/checks.js';
import { scoreFindings, gradeFor } from '../src/score.js';

function headersOf(obj) {
  return new Headers(obj);
}

test('HSTS missing on an https site is a fail', () => {
  const f = checkHsts(headersOf({}), true);
  assert.equal(f.status, 'fail');
});

test('HSTS with a tiny max-age is a warning', () => {
  const f = checkHsts(headersOf({ 'strict-transport-security': 'max-age=300' }), true);
  assert.equal(f.status, 'warn');
});

test('HSTS with a proper max-age passes', () => {
  const f = checkHsts(headersOf({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }), true);
  assert.equal(f.status, 'pass');
});

test('CSP with unsafe-inline is a warning, not a pass', () => {
  const f = checkCsp(headersOf({ 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'" }));
  assert.equal(f.status, 'warn');
});

test('frame-ancestors in CSP counts as clickjacking protection', () => {
  const f = checkFrameProtection(headersOf({ 'content-security-policy': "frame-ancestors 'none'" }));
  assert.equal(f.status, 'pass');
});

test('cookie without HttpOnly fails, missing only SameSite warns', () => {
  const h = headersOf({});
  h.getSetCookie = () => ['session=abc; Secure', 'pref=dark; Secure; HttpOnly'];
  const findings = checkCookies(h);
  assert.equal(findings[0].status, 'fail');
  assert.equal(findings[1].status, 'warn');
});

test('wildcard CORS with credentials is a fail', () => {
  const f = checkCors(
    headersOf({ 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' })
  );
  assert.equal(f.status, 'fail');
});

test('score only drops for fail and warn', () => {
  const score = scoreFindings([
    { status: 'fail' },
    { status: 'warn' },
    { status: 'pass' },
    { status: 'info' },
  ]);
  assert.equal(score, 79);
  assert.equal(gradeFor(score), 'B');
  assert.equal(gradeFor(100), 'A+');
  assert.equal(gradeFor(20), 'F');
});
