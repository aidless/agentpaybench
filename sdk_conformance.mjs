#!/usr/bin/env node
// Conformance probes against the *published* opcpay SDK (0.3.5), not the mock.
//
// The Python suite checks a server implementation. This file checks the other
// half of an integration: what the official client actually puts on the wire,
// and which client-side checks it leaves to the application.
//
// Run:
//   OPCPAY_SDK=/path/to/opcpay/index.mjs node sdk_conformance.mjs
//   # or: npm i --no-save opcpay@0.3.5 && node sdk_conformance.mjs
//
// No network: global fetch is replaced with a recorder.

import {createHmac} from 'node:crypto';
import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const candidate = process.env.OPCPAY_SDK || resolve('node_modules/opcpay/index.mjs');
if (!existsSync(candidate)) {
  console.error(`SKIP: opcpay SDK not found at ${candidate}`);
  console.error('Set OPCPAY_SDK or run: npm i --no-save opcpay@0.3.5');
  process.exit(2);
}
const {opcpay, opcpayError, verifyWebhook} = await import(pathToFileURL(candidate).href);

let failures = 0;
const tests = [];
const check = (name, fn) => tests.push({name, fn});
const eq = (actual, expected, label) => {
  const a = JSON.stringify(actual), b = JSON.stringify(expected);
  if (a !== b) throw new Error(`${label}: expected ${b}, got ${a}`);
};
const throws = (fn, label) => {
  try { fn(); } catch { return; }
  throw new Error(`${label}: did not throw`);
};
const rejects = async (fn, label) => {
  try { await fn(); } catch (e) { return e; }
  throw new Error(`${label}: did not reject`);
};

// --- fetch recorder -------------------------------------------------------
let calls = [];
let reply = {status: 200, body: {}};
globalThis.fetch = async (url, init = {}) => {
  const body = init.body ? JSON.parse(init.body) : undefined;
  calls.push({url: String(url), method: init.method, body,
              headers: init.headers, redirect: init.redirect});
  const text = JSON.stringify(reply.body ?? {});
  return new Response(text, {
    status: reply.status,
    headers: {'content-type': 'application/json', 'x-request-id': 'req_test'},
  });
};
const client = (baseURL = 'https://api.test/opcpay/api/pay/v1') =>
  new opcpay({apiKey: 'test_key', baseURL});
const last = () => calls[calls.length - 1];

// --- wire shape -----------------------------------------------------------
check('default base is the published one', () => {
  calls = []; reply = {status: 200, body: {}};
  const c = new opcpay({apiKey: 'test_key'});
  c.capabilities();
  eq(last().url, 'https://ai6666.com/opcpay/api/pay/v1/capabilities', 'url');
});

check('purchase path, method and full body', () => {
  calls = []; reply = {status: 200, body: {status: 'READY', idempotency_key: 'k1'}};
  client().purchase({userId: 'u1', idempotencyKey: 'k1', skuId: 'sku_count_10',
                     callbackURL: 'https://merchant.example.com/ok'});
  const c = last();
  eq(c.url, 'https://api.test/opcpay/api/pay/v1/purchase', 'url');
  eq(c.method, 'POST', 'method');
  eq(c.body, {user_id: 'u1', idempotency_key: 'k1', sku_id: 'sku_count_10',
              callback_url: 'https://merchant.example.com/ok'}, 'body');
  eq(c.redirect, 'error', 'redirect');
});

check('F1: missing idempotency key is dropped, not rejected locally', () => {
  calls = []; reply = {status: 200, body: {status: 'READY'}};
  client().purchase({userId: 'u1', skuId: 'sku_count_10'});
  const c = last();
  eq('idempotency_key' in c.body, false, 'idempotency_key present');
  eq('sku_id' in c.body, true, 'sku_id present');
});

check('F1b: missing idempotency key on consume is dropped too', () => {
  calls = []; reply = {status: 200, body: {status: 'SUCCEEDED'}};
  client().consume({userId: 'u1', amount: 1});
  eq('idempotency_key' in last().body, false, 'idempotency_key present');
});

check('F2: consume forwards 0, negative and NaN amounts', () => {
  for (const amount of [0, -3, NaN]) {
    calls = []; reply = {status: 200, body: {status: 'FAILED'}};
    client().consume({userId: 'u1', idempotencyKey: 'c1', amount});
    const sent = last().body.amount;
    const expected = Number.isNaN(amount) ? null : amount;
    eq(sent, expected, `amount ${String(amount)}`);
  }
});

check('F2b: access forwards amount=0', () => {
  calls = []; reply = {status: 200, body: {access_granted: false}};
  client().access('u1', 0);
  eq(last().body, {user_id: 'u1', amount: 0}, 'body');
});

check('access defaults amount to 1', () => {
  calls = []; reply = {status: 200, body: {access_granted: true}};
  client().access('u1');
  eq(last().body, {user_id: 'u1', amount: 1}, 'body');
});

check('transactionQuery posts to /transactions/query', () => {
  calls = []; reply = {status: 200, body: {status: 'PENDING'}};
  client().transactionQuery({user_id: 'u1', idempotency_key: 'k1'});
  eq(last().url, 'https://api.test/opcpay/api/pay/v1/transactions/query', 'url');
  eq(last().body, {user_id: 'u1', idempotency_key: 'k1'}, 'body');
});

check('transactionQuery does not validate its body locally', () => {
  calls = []; reply = {status: 200, body: {status: 'UNKNOWN'}};
  client().transactionQuery({});
  eq(last().body, {}, 'body');
});

check('reserved routes are still shipped as calls', async () => {
  calls = []; reply = {status: 501, body: {error: 'not implemented'}};
  const e = await rejects(() => client().refund({}), 'refund 501');
  eq(e.status, 501, 'status');
  eq(last().url, 'https://api.test/opcpay/api/pay/v1/refunds', 'url');
});

// --- error mapping --------------------------------------------------------
check('429 maps to retryable opcpayError', async () => {
  calls = []; reply = {status: 429, body: {error: 'slow down', error_code: 'RATE_LIMITED', retryable: true}};
  const e = await rejects(() => client().capabilities(), '429');
  eq(e instanceof opcpayError, true, 'type');
  eq(e.status, 429, 'status');
  eq(e.code, 'RATE_LIMITED', 'code');
  eq(e.retryable, true, 'retryable');
  eq(e.requestId, 'req_test', 'requestId');
});

check('400 is not retryable', async () => {
  calls = []; reply = {status: 400, body: {error: 'bad', error_code: 'BAD_REQUEST'}};
  const e = await rejects(() => client().access('u1'), '400');
  eq(e.retryable, false, 'retryable');
});

check('HTTPS base is enforced by the constructor', () => {
  throws(() => new opcpay({apiKey: 'k', baseURL: 'http://127.0.0.1:8787'}), 'http base');
});

// --- webhook verification -------------------------------------------------
const secret = 'whsec_test';
const rawEvent = (id = 'evt_1') => Buffer.from(JSON.stringify({
  id, type: 'entitlement.observed', project_id: 'p1', user_id: 'u1',
  created_at: '2026-11-22T00:00:00Z', data: {decision: 'ALLOW'},
}), 'utf8');
const signed = (raw, stamp, id = 'evt_1') => ({
  'yirenfu-timestamp': String(stamp),
  'yirenfu-signature': 'v1=' + createHmac('sha256', secret)
    .update(String(stamp) + '.').update(raw).digest('hex'),
  'yirenfu-event-id': id,
});
const now = Math.floor(Date.now() / 1000);

check('valid webhook returns the event', () => {
  const raw = rawEvent();
  eq(verifyWebhook(raw, signed(raw, now), secret, now).id, 'evt_1', 'id');
});

check('tampered body is rejected', () => {
  const raw = rawEvent();
  const h = signed(raw, now);
  throws(() => verifyWebhook(rawEvent('evt_2'), h, secret, now), 'tamper');
});

check('stale timestamp is rejected', () => {
  const raw = rawEvent();
  throws(() => verifyWebhook(raw, signed(raw, now - 301), secret, now), 'stale');
});

check('event-id header mismatch is rejected', () => {
  const raw = rawEvent();
  throws(() => verifyWebhook(raw, signed(raw, now, 'evt_other'), secret, now), 'id mismatch');
});

check('non-Buffer body is rejected (must verify before JSON.parse)', () => {
  throws(() => verifyWebhook(JSON.parse(rawEvent().toString()), signed(rawEvent(), now), secret, now),
         'parsed object');
});

check('F3: replayed webhook verifies twice (dedupe is the app\'s job)', () => {
  const raw = rawEvent();
  const h = signed(raw, now);
  eq(verifyWebhook(raw, h, secret, now).id, 'evt_1', 'first');
  eq(verifyWebhook(raw, h, secret, now).id, 'evt_1', 'second');
});

for (const {name, fn} of tests) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failures++; console.log(`FAIL ${name}: ${e.message}`); }
}
console.log(`\n${failures === 0 ? 'SDK CONFORMANCE OK' : `SDK CONFORMANCE FAILED (${failures})`}`);
process.exit(failures === 0 ? 0 : 1);
