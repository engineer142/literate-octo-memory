// scripts/check.js
//
// Проверка живости MTProto-прокси — порт checkOneServerTlsOnly /
// checkOneServerProtocol / checkOneServerFakeTlsProtocol из
// bogestv0-mtproto-checker/worker.js. Та же схема (Obfuscated2-рукопожатие,
// req_pq_multi, Fake-TLS ClientHello с HMAC-аутентификацией), но на Node
// net/crypto вместо cloudflare:sockets/crypto.subtle — раньше эта логика
// была "написана по памяти, не сверена построчно" (см. комментарии в
// оригинале), здесь она не переписана заново, а перенесена 1:1 по байтам,
// только API сокетов и крипто другое.
//
// ⚠️ Как и в оригинале — сама схема Obfuscated2/Fake-TLS реконструирована
// по общей схеме протокола, а не сверена построчно с mtprotoproxy/MTProxy.
// Перед тем как полагаться на данные, стоит вручную прогнать на нескольких
// заведомо живых серверах и проверить method:'protocol' vs 'tls-only'.
//
// вход:  data/candidates.json — [{ host, port, secret, region }, ...]
// выход: data/checked.json    — то же самое + { alive, pingMs, method,
//                                                checkedAt, attempts }
//
// Запуск: node scripts/check.js

import { readFile, writeFile } from 'node:fs/promises';
import { connect as netConnect } from 'node:net';
import { createHash, createHmac, createCipheriv, randomBytes as cryptoRandomBytes } from 'node:crypto';

const SOCKET_TIMEOUT_MS = Number(process.env.CHECK_TIMEOUT_MS || 5000);
// Node/GitHub Actions без лимита "50 подзапросов за вызов" — конкурентность
// можно держать сильно выше, чем 5 в Worker'е.
const CONCURRENCY = Number(process.env.CHECK_CONCURRENCY || 40);
const CHECK_ATTEMPTS = Number(process.env.CHECK_ATTEMPTS || 2);
const CHECK_RETRY_DELAY_MS = 700;
// Жёсткий потолок на весь прогон, независимо от того, что именно тормозит
// (DNS, сеть, сериализация где-то ещё) — если выбор не уложился, остаток
// кандидатов помечается method:'not-checked' и попадает в результат как
// "не проверено", а не бесконечно висит и не роняет job по timeout-minutes.
const WALL_CLOCK_BUDGET_MS = Number(process.env.CHECK_WALL_CLOCK_BUDGET_MS || 12 * 60 * 1000);

// ---------- байтовые утилиты ----------

function hexToBytes(hex) {
  hex = String(hex || '').replace(/[^0-9a-fA-F]/g, '');
  if (hex.length % 2 !== 0) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}

function concatBytes(...parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function sha256(bytes) {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

function hmacSha256(key, data) {
  return new Uint8Array(createHmac('sha256', key).update(data).digest());
}

function readUint32LE(bytes, offset) {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

// ---------- Obfuscated2: генерация nonce и деривация ключей ----------

const RESERVED_TAG_WORDS = [
  0x44414548, // 'HEAD'
  0x54534f50, // 'POST'
  0x20544547, // 'GET '
  0x4954504f, // 'OPTI'
  0xdddddddd,
  0xeeeeeeee,
  0x02010316,
];

function generateValidNonce() {
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const rnd = new Uint8Array(cryptoRandomBytes(64));
    if (rnd[0] === 0xef) continue;
    const firstWord = readUint32LE(rnd, 0);
    if (RESERVED_TAG_WORDS.indexOf(firstWord) !== -1) continue;
    const secondWord = readUint32LE(rnd, 4);
    if (secondWord === 0x00000000) continue;
    return rnd;
  }
}

function deriveKeyIv(nonce32, nonce16, secret16) {
  const key = sha256(concatBytes(nonce32, secret16)); // уже 32 байта
  return { key, iv: nonce16 };
}

// nonce[8:56] реверснуто (python-слайс nonce[55:7:-1])
function reversedMiddle(nonce64) {
  const out = new Uint8Array(48);
  for (let i = 0; i < 48; i++) out[i] = nonce64[55 - i];
  return out;
}

function deriveObfuscated2Keys(nonce64, secret16) {
  const encPart = nonce64.slice(8, 56);
  const enc = deriveKeyIv(encPart.slice(0, 32), encPart.slice(32, 48), secret16);

  const revPart = reversedMiddle(nonce64);
  const dec = deriveKeyIv(revPart.slice(0, 32), revPart.slice(32, 48), secret16);

  return { encKey: enc.key, encIv: enc.iv, decKey: dec.key, decIv: dec.iv };
}

// Прибавляет blocks (по 16 байт = 1 AES-блок) к 128-битному big-endian счётчику.
function incrementCounterBlocks(iv16, blocks) {
  const out = new Uint8Array(iv16);
  let carry = blocks;
  for (let i = 15; i >= 0 && carry > 0; i--) {
    const sum = out[i] + (carry & 0xff);
    out[i] = sum & 0xff;
    carry = (carry >> 8) + (sum > 0xff ? 1 : 0);
  }
  return out;
}

// AES-256-CTR с явным 128-битным счётчиком — Node увеличивает его по блокам
// точно так же, как WebCrypto AES-CTR с counter/length:128 в оригинале.
function aesCtrCrypt(keyBytes, counterBlock16, data) {
  const cipher = createCipheriv('aes-256-ctr', Buffer.from(keyBytes), Buffer.from(counterBlock16));
  return new Uint8Array(Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()]));
}

async function buildObfuscatedHandshake(secret16) {
  const nonce = new Uint8Array(generateValidNonce());

  const PROTO_TAG_ABRIDGED = [0xef, 0xef, 0xef, 0xef];
  const DC_ID = 2;

  nonce[56] = PROTO_TAG_ABRIDGED[0];
  nonce[57] = PROTO_TAG_ABRIDGED[1];
  nonce[58] = PROTO_TAG_ABRIDGED[2];
  nonce[59] = PROTO_TAG_ABRIDGED[3];
  nonce[60] = DC_ID & 0xff;
  nonce[61] = (DC_ID >> 8) & 0xff;
  nonce[62] = 0x00;
  nonce[63] = 0x00;

  const keys = deriveObfuscated2Keys(nonce, secret16);
  const fullCipher = aesCtrCrypt(keys.encKey, keys.encIv, nonce);

  const wireHeader = new Uint8Array(64);
  wireHeader.set(nonce.slice(0, 56), 0);
  wireHeader.set(fullCipher.slice(56, 64), 56);

  return { wireHeader, encKey: keys.encKey, encIv: keys.encIv, decKey: keys.decKey, decIv: keys.decIv };
}

// req_pq_multi#be7e8ef1 nonce:int128 = ResPQ
function buildReqPqMultiEnvelope() {
  const nonce16 = new Uint8Array(cryptoRandomBytes(16));
  const constructorLE = new Uint8Array([0xf1, 0x8e, 0x7e, 0xbe]);
  const body = concatBytes(constructorLE, nonce16); // 20 байт

  const authKeyId = new Uint8Array(8);
  const messageId = new Uint8Array(8);
  let v = (BigInt(Date.now()) * 4294967296n) / 1000n;
  for (let i = 0; i < 8; i++) { messageId[i] = Number(v & 0xffn); v >>= 8n; }

  const lenBytes = new Uint8Array(4);
  lenBytes[0] = body.length & 0xff;

  const envelope = concatBytes(authKeyId, messageId, lenBytes, body);

  const lenDiv4 = envelope.length / 4;
  const framed = new Uint8Array(1 + envelope.length);
  framed[0] = lenDiv4;
  framed.set(envelope, 1);

  return { framed, nonce16 };
}

// ---------- Fake-TLS ClientHello ----------

function parseEeSecret(secretRaw) {
  let secret = String(secretRaw || '');
  if (/^ee/i.test(secret)) secret = secret.slice(2);

  const secret16 = hexToBytes(secret.slice(0, 32));

  let domainBytes;
  if (secret.length > 32) {
    domainBytes = hexToBytes(secret.slice(32));
  } else {
    domainBytes = new TextEncoder().encode('t.me');
  }
  if (!domainBytes || domainBytes.length === 0) domainBytes = new TextEncoder().encode('google.com');
  return { secret16, domainBytes };
}

function buildTlsClientHelloBytes(domainBytes, randomBytes32) {
  const bytes = [];
  const pushBytes = (arr) => { for (let i = 0; i < arr.length; i++) bytes.push(arr[i]); };
  const randomBytes = (n) => new Uint8Array(cryptoRandomBytes(n));

  bytes.push(0x16, 0x03, 0x01, 0x00, 0x00);
  const handshakeStart = bytes.length;
  bytes.push(0x01, 0x00, 0x00, 0x00);
  bytes.push(0x03, 0x03);
  pushBytes(randomBytes32);
  bytes.push(0x20);
  pushBytes(randomBytes(32));
  bytes.push(0x00, 0x12);
  pushBytes([0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
    0xC0, 0x2B, 0xC0, 0x2F, 0xC0, 0x2C, 0xC0, 0x30,
    0x00, 0x9C, 0x00, 0x9D]);
  bytes.push(0x01, 0x00);

  const extensionsLenOffset = bytes.length;
  bytes.push(0x00, 0x00);

  bytes.push(0x00, 0x00);
  const sniLenOffset = bytes.length;
  bytes.push(0x00, 0x00);
  const listLenOffset = bytes.length;
  bytes.push(0x00, 0x00);
  bytes.push(0x00);
  bytes.push((domainBytes.length >> 8) & 0xFF, domainBytes.length & 0xFF);
  pushBytes(domainBytes);

  const total = bytes.length;

  const listLen = total - listLenOffset - 2;
  bytes[listLenOffset] = (listLen >> 8) & 0xFF;
  bytes[listLenOffset + 1] = listLen & 0xFF;

  const sniLen = total - sniLenOffset - 2;
  bytes[sniLenOffset] = (sniLen >> 8) & 0xFF;
  bytes[sniLenOffset + 1] = sniLen & 0xFF;

  const extLen = total - extensionsLenOffset - 2;
  bytes[extensionsLenOffset] = (extLen >> 8) & 0xFF;
  bytes[extensionsLenOffset + 1] = extLen & 0xFF;

  const handshakeLen = bytes.length - handshakeStart - 4;
  bytes[handshakeStart + 1] = (handshakeLen >> 16) & 0xFF;
  bytes[handshakeStart + 2] = (handshakeLen >> 8) & 0xFF;
  bytes[handshakeStart + 3] = handshakeLen & 0xFF;

  const recordLen = bytes.length - 5;
  bytes[3] = (recordLen >> 8) & 0xFF;
  bytes[4] = recordLen & 0xFF;

  return new Uint8Array(bytes);
}

function buildFakeTlsClientHello(secretRaw) {
  const parsed = parseEeSecret(secretRaw);
  const randomBytes32 = new Uint8Array(cryptoRandomBytes(32));
  return buildTlsClientHelloBytes(parsed.domainBytes, randomBytes32);
}

function buildFakeTlsClientHelloAuthenticated(secret16, domainBytes) {
  const zeroRandom = new Uint8Array(32);
  const helloWithZeroRandom = buildTlsClientHelloBytes(domainBytes, zeroRandom);
  const digest = hmacSha256(secret16, helloWithZeroRandom); // 32 байта

  const hello = new Uint8Array(helloWithZeroRandom);
  hello.set(digest, 11);
  return hello;
}

function wrapTlsApplicationData(data) {
  const out = new Uint8Array(5 + data.length);
  out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
  out[3] = (data.length >> 8) & 0xff; out[4] = data.length & 0xff;
  out.set(data, 5);
  return out;
}

// ---------- сокеты: Node net вместо cloudflare:sockets ----------

function openSocket(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('connect timeout'));
    }, timeoutMs);
    socket.once('connect', () => { clearTimeout(timer); resolve(socket); });
    socket.once('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

// Обёртка над потоковым net.Socket с интерфейсом .read(), похожим на
// ReadableStreamDefaultReader из Workers (чтобы логика ниже была портирована
// с минимумом изменений).
function createSocketReader(socket) {
  const pending = [];
  let waiting = null;
  let ended = false;
  let error = null;

  socket.on('data', (chunk) => {
    const value = new Uint8Array(chunk);
    if (waiting) { const r = waiting; waiting = null; r({ value, done: false }); }
    else pending.push(value);
  });
  const finish = () => { ended = true; if (waiting) { const r = waiting; waiting = null; r({ done: true }); } };
  socket.on('end', finish);
  socket.on('close', finish);
  socket.on('error', (e) => { error = e; finish(); });

  return {
    async read() {
      if (pending.length) return { value: pending.shift(), done: false };
      if (error) throw error;
      if (ended) return { done: true };
      return new Promise((resolve) => { waiting = resolve; });
    },
  };
}

// ---------- Часть A: старая проверка (поддельный TLS ClientHello) ----------

async function checkOneServerTlsOnly(host, port, secret) {
  const start = Date.now();
  let socket = null;
  let timedOut = false;

  const timeoutPromise = new Promise((resolve) => {
    setTimeout(() => { timedOut = true; resolve({ alive: false, pingMs: null }); }, SOCKET_TIMEOUT_MS);
  });

  const checkPromise = (async () => {
    try {
      socket = await openSocket(host, port, SOCKET_TIMEOUT_MS);
      const reader = createSocketReader(socket);

      const request = buildFakeTlsClientHello(secret);
      socket.write(Buffer.from(request));

      const { value } = await reader.read();
      if (timedOut) return { alive: false, pingMs: null };

      const pingMs = Date.now() - start;
      const alive = !!(value && value.length > 0 && value[0] === 0x16);
      return { alive, pingMs };
    } catch {
      return { alive: false, pingMs: null };
    } finally {
      try { socket && socket.destroy(); } catch { /* noop */ }
    }
  })();

  return Promise.race([checkPromise, timeoutPromise]);
}

// ---------- Часть B: настоящий MTProto-пинг (Obfuscated2 + req_pq_multi) ----------

async function checkOneServerProtocol(host, port, secret16) {
  const start = Date.now();
  let socket = null;
  let timedOut = false;

  const timeoutPromise = new Promise((resolve) => {
    setTimeout(() => { timedOut = true; resolve({ alive: false, pingMs: null }); }, SOCKET_TIMEOUT_MS);
  });

  const checkPromise = (async () => {
    try {
      const hs = await buildObfuscatedHandshake(secret16);
      const msg = buildReqPqMultiEnvelope();

      const counterAfterHeader = incrementCounterBlocks(hs.encIv, 4);
      const cipherPayload = aesCtrCrypt(hs.encKey, counterAfterHeader, msg.framed);

      socket = await openSocket(host, port, SOCKET_TIMEOUT_MS);
      const reader = createSocketReader(socket);

      socket.write(Buffer.from(hs.wireHeader));
      socket.write(Buffer.from(cipherPayload));

      let received = new Uint8Array(0);

      // eslint-disable-next-line no-constant-condition
      while (true) {
        if (timedOut) return { alive: false, pingMs: null };
        const chunk = await reader.read();
        if (chunk.done) break;
        received = concatBytes(received, chunk.value);

        if (received.length >= 1) {
          const plain = aesCtrCrypt(hs.decKey, hs.decIv, received);
          const lenByte = plain[0];
          let expectedTotal;
          if (lenByte < 127) {
            expectedTotal = 1 + lenByte * 4;
          } else {
            if (plain.length < 4) continue;
            expectedTotal = 4 + (plain[1] | (plain[2] << 8) | (plain[3] << 16));
          }
          if (received.length >= expectedTotal) {
            if (timedOut) return { alive: false, pingMs: null };

            const pingMs = Date.now() - start;
            const bodyOffset = lenByte < 127 ? 1 : 4;
            const constructorOffset = bodyOffset + 8 + 8 + 4;
            let alive = false;
            if (plain.length >= constructorOffset + 4) {
              const ctor = (plain[constructorOffset] | (plain[constructorOffset + 1] << 8) |
                (plain[constructorOffset + 2] << 16) | (plain[constructorOffset + 3] << 24)) >>> 0;
              alive = ctor === 0x05162463 || plain.length > bodyOffset + 20;
            }
            return { alive, pingMs };
          }
        }
      }
      return { alive: false, pingMs: null };
    } catch {
      return { alive: false, pingMs: null };
    } finally {
      try { socket && socket.destroy(); } catch { /* noop */ }
    }
  })();

  return Promise.race([checkPromise, timeoutPromise]);
}

// ---------- Fake-TLS + протокол вместе (для секретов "ee") ----------

async function checkOneServerFakeTlsProtocol(host, port, secretRaw) {
  const start = Date.now();
  let socket = null;
  let timedOut = false;
  let fallbackResult = { alive: false, pingMs: null, method: 'tls-only' };

  const timeoutPromise = new Promise((resolve) => {
    setTimeout(() => { timedOut = true; resolve(fallbackResult); }, SOCKET_TIMEOUT_MS);
  });

  const checkPromise = (async () => {
    try {
      const parsed = parseEeSecret(secretRaw);
      if (parsed.secret16.length !== 16) {
        const tls = await checkOneServerTlsOnly(host, port, secretRaw);
        return { method: 'tls-only', ...tls };
      }

      const hello = buildFakeTlsClientHelloAuthenticated(parsed.secret16, parsed.domainBytes);

      socket = await openSocket(host, port, SOCKET_TIMEOUT_MS);
      const reader = createSocketReader(socket);

      socket.write(Buffer.from(hello));

      const firstRead = await reader.read();
      if (timedOut) return fallbackResult;
      if (firstRead.done || !firstRead.value || firstRead.value.length === 0 || firstRead.value[0] !== 0x16) {
        return { alive: false, pingMs: null, method: 'tls-only' };
      }
      fallbackResult = { alive: true, pingMs: Date.now() - start, method: 'tls-only' };

      let buf = new Uint8Array(firstRead.value);

      const hs = await buildObfuscatedHandshake(parsed.secret16);
      const msg = buildReqPqMultiEnvelope();
      const counterAfterHeader = incrementCounterBlocks(hs.encIv, 4);
      const cipherPayload = aesCtrCrypt(hs.encKey, counterAfterHeader, msg.framed);
      const innerPlain = concatBytes(hs.wireHeader, cipherPayload);
      const tlsRecord = wrapTlsApplicationData(innerPlain);

      socket.write(Buffer.from(tlsRecord));

      let appPayload = new Uint8Array(0);

      // eslint-disable-next-line no-constant-condition
      while (true) {
        if (timedOut) return fallbackResult;

        let offset = 0;
        while (buf.length - offset >= 5) {
          const recType = buf[offset];
          const recLen = (buf[offset + 3] << 8) | buf[offset + 4];
          if (buf.length - offset < 5 + recLen) break;
          if (recType === 0x17) appPayload = concatBytes(appPayload, buf.slice(offset + 5, offset + 5 + recLen));
          offset += 5 + recLen;
        }
        buf = buf.slice(offset);

        if (appPayload.length >= 1) {
          const plain = aesCtrCrypt(hs.decKey, hs.decIv, appPayload);
          const lenByte = plain[0];
          const expectedTotal = lenByte < 127
            ? (1 + lenByte * 4)
            : (plain.length >= 4 ? 4 + (plain[1] | (plain[2] << 8) | (plain[3] << 16)) : null);

          if (expectedTotal != null && appPayload.length >= expectedTotal) {
            if (timedOut) return fallbackResult;
            const pingMs = Date.now() - start;
            const bodyOffset = lenByte < 127 ? 1 : 4;
            const constructorOffset = bodyOffset + 8 + 8 + 4;
            let alive = plain.length > bodyOffset + 20;
            if (plain.length >= constructorOffset + 4) {
              const ctor = (plain[constructorOffset] | (plain[constructorOffset + 1] << 8) |
                (plain[constructorOffset + 2] << 16) | (plain[constructorOffset + 3] << 24)) >>> 0;
              alive = alive || ctor === 0x05162463;
            }
            return { alive, pingMs, method: 'protocol' };
          }
        }

        const chunk = await reader.read();
        if (chunk.done) return fallbackResult;
        buf = concatBytes(buf, chunk.value);
      }
    } catch {
      return fallbackResult;
    } finally {
      try { socket && socket.destroy(); } catch { /* noop */ }
    }
  })();

  return Promise.race([checkPromise, timeoutPromise]);
}

// ---------- выбор метода по типу секрета + ретраи ----------

async function checkOneServerAttempt(host, port, secretRaw) {
  const secret = String(secretRaw || '');
  if (/^ee/i.test(secret)) return checkOneServerFakeTlsProtocol(host, port, secret);

  let clean = secret;
  if (/^dd/i.test(clean)) clean = clean.slice(2);
  const secret16 = hexToBytes(clean.slice(0, 32));
  if (secret16.length !== 16) {
    const fb = await checkOneServerTlsOnly(host, port, secret);
    return { method: 'tls-only', ...fb };
  }

  const pr = await checkOneServerProtocol(host, port, secret16);
  return { method: 'protocol', ...pr };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function checkOneServer(host, port, secretRaw) {
  let lastResult = null;
  for (let attempt = 1; attempt <= CHECK_ATTEMPTS; attempt++) {
    const result = await checkOneServerAttempt(host, port, secretRaw);
    lastResult = result;
    if (result.alive) return { ...result, attempts: attempt };
    if (attempt < CHECK_ATTEMPTS) await sleep(CHECK_RETRY_DELAY_MS);
  }
  return { ...lastResult, attempts: CHECK_ATTEMPTS };
}

// ---------- пул конкурентности + main ----------

async function mapWithConcurrency(items, limit, fn, results, deadlineTs, onSkip) {
  let i = 0;
  async function worker() {
    while (i < items.length) {
      const idx = i++;
      if (Date.now() >= deadlineTs) {
        results[idx] = onSkip(items[idx]);
        continue;
      }
      results[idx] = await fn(items[idx], idx);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

function notCheckedResult(c) {
  return { ...c, alive: false, pingMs: null, method: 'not-checked', attempts: 0, checkedAt: new Date().toISOString() };
}

async function main() {
  const raw = await readFile('data/candidates.json', 'utf8');
  const candidates = JSON.parse(raw);

  // Предзаполняем "не проверено" — если жёсткий таймер сработает раньше,
  // чем цикл естественным образом дойдёт до элемента, тут уже будет что
  // писать, а не null/undefined.
  const results = candidates.map(notCheckedResult);

  const deadlineTs = Date.now() + WALL_CLOCK_BUDGET_MS;
  console.log(
    `[check] кандидатов: ${candidates.length}, конкурентность: ${CONCURRENCY}, попыток: ${CHECK_ATTEMPTS}, ` +
    `бюджет времени: ${Math.round(WALL_CLOCK_BUDGET_MS / 1000)}с`
  );

  let finished = false;

  async function writeResultsAndExit(reason) {
    if (finished) return;
    finished = true;
    const aliveCount = results.filter((r) => r.alive).length;
    const notChecked = results.filter((r) => r.method === 'not-checked').length;
    console.log(`[check] ${reason}: ${aliveCount}/${results.length} живых, не проверено: ${notChecked}`);
    await writeFile('data/checked.json', JSON.stringify(results, null, 2));
    console.log('[check] записано в data/checked.json');
  }

  // ЖЁСТКИЙ стоп верхнего уровня: не полагается на то, что рабочий цикл
  // сам заметит дедлайн между элементами — просто пишет то, что накопилось
  // в results на данный момент, и завершает процесс. Это и есть настоящая
  // гарантия, что скрипт не выйдет за бюджет, даже если сама очередь идёт
  // медленнее, чем ожидалось.
  const hardTimer = setTimeout(async () => {
    console.warn('[check] ЖЁСТКИЙ таймаут бюджета — принудительно завершаю с частичным результатом');
    await writeResultsAndExit('прервано по таймауту');
    process.exit(0);
  }, WALL_CLOCK_BUDGET_MS + 5000); // +5с запаса поверх мягкого дедлайна, чтобы сначала попробовать штатный путь
  hardTimer.unref?.(); // не мешает процессу завершиться самому, если успел раньше

  let done = 0;
  await mapWithConcurrency(
    candidates,
    CONCURRENCY,
    async (c) => {
      const r = await checkOneServer(c.host, c.port, c.secret);
      done++;
      if (done % 100 === 0) console.log(`[check] обработано ${done}/${candidates.length}`);
      return {
        ...c,
        alive: r.alive,
        pingMs: r.pingMs ?? null,
        method: r.method ?? null,
        attempts: r.attempts ?? null,
        checkedAt: new Date().toISOString(),
      };
    },
    results,
    deadlineTs,
    notCheckedResult
  );

  clearTimeout(hardTimer);
  await writeResultsAndExit('готово');
}

main().catch((e) => {
  console.error('[check] фатальная ошибка:', e);
  process.exit(1);
});
