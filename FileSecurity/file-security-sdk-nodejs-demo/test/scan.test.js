import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanIsClean, malwareScan, ScanFailure } from '../scan.js';
import { app, secureFilename } from '../app.js';

test('respuesta compacta y datos desconocidos', () => {
  for (const r of [{ scanResult: null }, { scanResult: 0 }, { scanResult: 0, foundMalwares: [] }]) assert.ok(scanIsClean(r));
  for (const r of [{ scanResult: 1 }, { scanResult: 2 }, {}, [], null, { result: {} }, { result: null },
    { scanResult: 0, foundMalwares: [{ malwareName: 'x' }] }, { scanResult: 0, foundErrors: [{ name: 'e' }] }]) assert.equal(scanIsClean(r), false);
});

test('respuesta verbose por motor', () => {
  const clean = { malwareCount: 0, malware: null, error: null };
  assert.ok(scanIsClean({ result: { atse: clean, trendx: clean } }));
  for (const e of [{ ...clean, malwareCount: 1 }, { ...clean, malware: [{ name: 'x' }] }, { ...clean, error: { m: 1 } }, {}, null])
    assert.equal(scanIsClean({ result: { atse: clean, trendx: e } }), false);
});

test('malwareScan: pml=true, logs completos y close() siempre', async () => {
  process.env.V1_API_KEY = 'k'; process.env.V1_REGION = 'us-east-1';
  const calls = []; let closed = 0;
  const createClient = () => ({ scanBuffer: async (...a) => { calls.push(a); return { scanResult: 0, scanId: 'id', extra: { nested: [1] } }; }, close: () => closed++ });
  const out = await malwareScan(Buffer.from('test'), 'sample.txt', { createClient });
  assert.ok(out.accepted);
  assert.deepEqual(out.response.extra, { nested: [1] });
  assert.equal(calls[0][0], 'sample.txt'); assert.equal(calls[0][3], true);
  assert.equal(closed, 1);
});

test('malwareScan: error de autenticación -> alerta controlada, sin texto crudo', async () => {
  process.env.V1_API_KEY = 'k';
  let closed = 0;
  const createClient = () => ({ scanBuffer: async () => { throw new Error('You are not authenticated. Invalid token or key SECRET'); }, close: () => closed++ });
  await assert.rejects(malwareScan(Buffer.from('x'), 'a.txt', { createClient }), e =>
    e instanceof ScanFailure && /rechazó la API key/.test(e.message) && !e.message.includes('SECRET'));
  assert.equal(closed, 1);
});

test('secureFilename', () => {
  assert.equal(secureFilename('../../etc/passwd'), 'passwd');
  assert.equal(secureFilename('mi archivo ñ.pdf'), 'mi_archivo_n.pdf');
});

test('HTTP: health y validaciones sin llamar al SDK', async () => {
  const srv = app.listen(0); const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    assert.deepEqual(await (await fetch(`${base}/health`)).json(), { status: 'ok' });
    const fd = new FormData(); fd.append('file', new Blob(['x']), 'malo.exe');
    assert.match(await (await fetch(base, { method: 'POST', body: fd })).text(), /Tipo de archivo no permitido/);
    const big = new FormData(); big.append('file', new Blob([new Uint8Array(16 * 1024 * 1024 + 1)]), 'a.txt');
    assert.equal((await fetch(base, { method: 'POST', body: big })).status, 413);
  } finally { srv.close(); }
});
