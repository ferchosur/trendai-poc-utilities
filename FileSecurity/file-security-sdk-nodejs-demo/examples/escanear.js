// Ejemplo mínimo del SDK de File Security para Node.js.
// Uso: node --env-file=.env examples/escanear.js <archivo>   |   node --env-file=.env examples/escanear.js --eicar
import { readFile } from 'node:fs/promises';
import { AmaasGrpcClient } from 'file-security-sdk';

const target = process.argv[2];
if (!target) {
  console.error('Uso: node examples/escanear.js <archivo> | --eicar');
  process.exit(2);
}

// Archivo de prueba EICAR generado en memoria (se arma por partes para que el antivirus local no borre este script).
const eicar = () => Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-' + 'TEST-FILE!$H+H*');

const client = new AmaasGrpcClient(process.env.V1_REGION, process.env.V1_API_KEY);
try {
  const [name, bytes] = target === '--eicar' ? ['eicar-en-memoria.txt', eicar()] : [target, await readFile(target)];
  const started = performance.now();
  const result = await client.scanBuffer(name, bytes, ['demo-nodejs'], true); // pml = true
  const ms = Math.round(performance.now() - started);
  console.log(result.scanResult === 0 ? `LIMPIO  ${name}  (${ms} ms)` : `MALICIOSO  ${name}  (${ms} ms)`);
  for (const m of result.foundMalwares ?? []) console.log(`  malware: ${m.malwareName}`);
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.scanResult === 0 ? 0 : 1;
} catch (error) {
  console.error('Error de File Security:', error.message);
  process.exitCode = 3;
} finally {
  client.close();
}
