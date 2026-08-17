// scripts/check.js
//
// ЗАГЛУШКА. Читает data/candidates.json (результат collect.js) и пока
// просто помечает каждого кандидата как "не проверен" — реальный
// MTProto/Fake-TLS пинг (порт Obfuscated2-рукопожатия из worker.js на
// Node net/tls) добавим отдельным шагом.
//
// Контракт на будущее (чтобы push-firestore.js мог писаться параллельно):
//   вход:  data/candidates.json  — [{ host, port, secret, region }, ...]
//   выход: data/checked.json     — [{ host, port, secret, region,
//                                      alive, pingMs, method, checkedAt }, ...]
//   method: 'protocol' | 'tls-only' | null (пока всегда null — заглушка)
//
// Запуск: node scripts/check.js

import { readFile, writeFile } from 'node:fs/promises';

async function main() {
  const raw = await readFile('data/candidates.json', 'utf8');
  const candidates = JSON.parse(raw);

  console.log(`[check] кандидатов на входе: ${candidates.length}`);
  console.log('[check] ЗАГЛУШКА: реальная проверка живости ещё не реализована');

  const now = new Date().toISOString();
  const checked = candidates.map((c) => ({
    ...c,
    alive: null, // null = "не проверялось", не путать с false ("проверили — не отвечает")
    pingMs: null,
    method: null,
    checkedAt: now,
  }));

  await writeFile('data/checked.json', JSON.stringify(checked, null, 2));
  console.log('[check] записано в data/checked.json (без реальной проверки)');
}

main().catch((e) => {
  console.error('[check] фатальная ошибка:', e);
  process.exit(1);
});
