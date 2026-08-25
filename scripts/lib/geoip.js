// scripts/lib/geoip.js
//
// Определение РЕАЛЬНОГО региона прокси по IP-адресу (а не по домену
// маскировки из секрета, как раньше в collectDetectRegion). Два шага:
//
//   1. host -> ip        — DNS lookup (node:dns/promises), с кэшем в памяти
//                           на время одного прогона (один host может
//                           встречаться на разных портах/секретах).
//   2. ip -> страна/координаты — батч-запрос к ip-api.com (бесплатно, без
//                           ключа, до 100 IP за один POST /batch, поля
//                           countryCode/continentCode/lat/lon/city).
//                           Результат кэшируется на диск
//                           (data/geoip-cache.json) на GEOIP_CACHE_TTL_MS,
//                           чтобы не жечь лимит 45 запросов/мин на одни и
//                           те же IP каждый прогон (proxy-sync гоняется раз
//                           в 40 минут). Записи старше GEOIP_CACHE_TTL_MS
//                           удаляются из файла перед каждой записью на
//                           диск (см. pruneExpiredCache) — иначе кэш растёт
//                           бесконечно и каждый коммит в git раздувается
//                           мёртвыми IP из давно исчезнувших источников.
//
// Устойчивость к сбоям ip-api.com:
//   - при 429/сетевой ошибке — до GEOIP_MAX_RETRIES повторов с backoff
//     (учитывается заголовок Retry-After на 429, иначе экспоненциальная
//     задержка);
//   - если и после всех повторов батч не прошёл — переключаемся на
//     резервного провайдера ipwho.is (тоже бесплатный, без ключа, но без
//     батч-эндпоинта — опрашивается по одному IP с ограниченной
//     конкурентностью). Это происходит только для конкретного
//     проблемного чанка, а не для всего прогона — если ip-api.com отошёл
//     после временного сбоя, следующие чанки снова пойдут через него.
//
// lat/lon нужны не для фильтра "город = город" (для дата-центровых IP это
// ненадёжно — геолокация часто указывает на офис хостера, а не физическое
// расположение сервера), а для СОРТИРОВКИ прокси по расстоянию до
// посетителя (гаверсинус) на стороне checker-vps/бэкенда — это следующий
// шаг, здесь только собираются сырые координаты.
//
// ip-api.com бесплатный тариф — только HTTP, не HTTPS (HTTPS платный).
// Это ок для сервера (GitHub Actions), не для браузера/клиента.
// ipwho.is (резерв) — HTTPS, тоже бесплатный без ключа.
//
// Итоговый бакет региона — тот же набор, что и раньше (ru/us/asia/eu),
// чтобы push-firestore.js и фронтенд не пришлось менять:
//   ru   — Россия + соседи по СНГ + Иран/Туркменистан (страны из тех же
//          источников, что помечены "iran-russia" — общий бакет "обход
//          блокировок в регионе повышенной цензуры")
//   us   — США, Канада, остальная Северная Америка
//   asia — континент Asia, кроме уже попавших в ru-бакет (Иран и т.д.)
//   eu   — всё остальное (Европа, Африка, Юж. Америка, Океания) — то же
//          поведение "по умолчанию", что было в collectDetectRegion

import { readFile, writeFile } from 'node:fs/promises';
import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';

const GEOIP_CACHE_PATH = 'data/geoip-cache.json';
const GEOIP_CACHE_TTL_MS = Number(process.env.GEOIP_CACHE_TTL_MS || 7 * 24 * 60 * 60 * 1000); // 7 дней
const GEOIP_BATCH_SIZE = 100; // потолок ip-api.com /batch
const GEOIP_BATCH_DELAY_MS = Number(process.env.GEOIP_BATCH_DELAY_MS || 1500); // держим запас под 45 req/min
const GEOIP_FETCH_TIMEOUT_MS = Number(process.env.GEOIP_FETCH_TIMEOUT_MS || 8000);
const DNS_LOOKUP_CONCURRENCY = Number(process.env.DNS_LOOKUP_CONCURRENCY || 30);
const GEOIP_MAX_RETRIES = Number(process.env.GEOIP_MAX_RETRIES || 3);
const GEOIP_RETRY_BASE_DELAY_MS = Number(process.env.GEOIP_RETRY_BASE_DELAY_MS || 2000);
const GEOIP_FALLBACK_CONCURRENCY = Number(process.env.GEOIP_FALLBACK_CONCURRENCY || 10);
const GEOIP_FALLBACK_TIMEOUT_MS = Number(process.env.GEOIP_FALLBACK_TIMEOUT_MS || 5000);

const RU_BUCKET_COUNTRIES = new Set(['RU', 'BY', 'KZ', 'KG', 'TJ', 'TM', 'UZ', 'IR', 'AM', 'AZ', 'GE', 'MD']);
const US_BUCKET_COUNTRIES = new Set(['US', 'CA', 'MX']);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------- шаг 1: host -> ip (с кэшем на прогон) ----------

export function createDnsCache() {
  return new Map(); // host -> ip | null
}

async function resolveOneHost(host, cache) {
  if (cache.has(host)) return cache.get(host);
  if (isIP(host)) { cache.set(host, host); return host; }
  try {
    const { address } = await dnsLookup(host, { family: 4 });
    cache.set(host, address);
    return address;
  } catch {
    cache.set(host, null);
    return null;
  }
}

// Резолвит список хостов в ip с ограниченной конкурентностью.
// Возвращает Map host -> ip|null.
export async function resolveHosts(hosts, cache = createDnsCache()) {
  const unique = Array.from(new Set(hosts));
  let i = 0;
  async function worker() {
    while (i < unique.length) {
      const idx = i++;
      await resolveOneHost(unique[idx], cache);
    }
  }
  await Promise.all(Array.from({ length: Math.min(DNS_LOOKUP_CONCURRENCY, unique.length) }, worker));
  return cache;
}

// ---------- шаг 2: ip -> страна (кэш на диске + батч-запросы) ----------

async function loadDiskCache() {
  try {
    const raw = await readFile(GEOIP_CACHE_PATH, 'utf8');
    const data = JSON.parse(raw);
    return data && typeof data === 'object' ? data : {};
  } catch {
    return {};
  }
}

async function saveDiskCache(cache) {
  try {
    await writeFile(GEOIP_CACHE_PATH, JSON.stringify(cache, null, 2));
  } catch (e) {
    console.warn(`[geoip] не удалось записать кэш: ${e.message}`);
  }
}

// Удаляет из кэша записи старше GEOIP_CACHE_TTL_MS ПЕРЕД записью на диск.
// Без этого data/geoip-cache.json растёт бесконечно: TTL и так не даёт
// использовать устаревшую запись (geolocateIps/peekCachedGeo её просто
// пропускают), но сама запись остаётся в файле навсегда — тысячи мёртвых
// IP из давно исчезнувших источников продолжают коммититься в git каждый
// прогон (proxy-sync гоняется раз в 40 минут), раздувая и файл, и историю
// репозитория. Мутирует cache на месте и возвращает число удалённых записей.
function pruneExpiredCache(cache, now) {
  let removed = 0;
  for (const ip of Object.keys(cache)) {
    const entry = cache[ip];
    if (!entry || typeof entry.fetchedAt !== 'number' || now - entry.fetchedAt >= GEOIP_CACHE_TTL_MS) {
      delete cache[ip];
      removed++;
    }
  }
  return removed;
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(t);
  }
}

// ---------- основной провайдер: ip-api.com (батч, до 100 IP за запрос) ----------

// Один запрос к /batch. Возвращает { items, retryAfterSeconds }:
//   items === null       — запрос не удался (сеть/таймаут/HTTP-ошибка/429)
//   items === []/[...]   — запрос удался, просто может не быть success-строк
//   retryAfterSeconds    — значение заголовка Retry-After на 429, если было
async function geoBatchRequestOnce(ips) {
  const fields = 'status,message,countryCode,continentCode,lat,lon,city,query';
  const body = JSON.stringify(ips.map((ip) => ({ query: ip, fields })));
  try {
    const res = await fetchWithTimeout(
      'http://ip-api.com/batch',
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body },
      GEOIP_FETCH_TIMEOUT_MS
    );
    if (res.status === 429) {
      const h = res.headers && typeof res.headers.get === 'function' ? res.headers.get('retry-after') : null;
      const retryAfterSeconds = h ? Number(h) : null;
      console.warn('[geoip] ip-api.com/batch — 429 (рейт-лимит)' + (retryAfterSeconds ? `, retry-after=${retryAfterSeconds}с` : ''));
      return { items: null, retryAfterSeconds: Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : null };
    }
    if (!res.ok) {
      console.warn(`[geoip] ip-api.com/batch — HTTP ${res.status}`);
      return { items: null, retryAfterSeconds: null };
    }
    const data = await res.json();
    return { items: Array.isArray(data) ? data : [], retryAfterSeconds: null };
  } catch (e) {
    console.warn(`[geoip] ip-api.com/batch — ошибка: ${e.message}`);
    return { items: null, retryAfterSeconds: null };
  }
}

// Обёртка с повторами: до GEOIP_MAX_RETRIES дополнительных попыток,
// экспоненциальный backoff (или Retry-After с 429, если сервер его прислал).
// Возвращает массив items при успехе, null — если провайдер так и не
// ответил после всех попыток (вызывающий код переключается на fallback).
async function geoBatchRequestWithRetry(ips) {
  for (let attempt = 0; attempt <= GEOIP_MAX_RETRIES; attempt++) {
    const { items, retryAfterSeconds } = await geoBatchRequestOnce(ips);
    if (items !== null) return items;
    if (attempt === GEOIP_MAX_RETRIES) break;
    const delayMs = retryAfterSeconds != null
      ? retryAfterSeconds * 1000
      : GEOIP_RETRY_BASE_DELAY_MS * 2 ** attempt;
    console.warn(`[geoip] ip-api.com/batch — попытка ${attempt + 1}/${GEOIP_MAX_RETRIES + 1} не удалась, повтор через ${delayMs}мс`);
    await sleep(delayMs);
  }
  return null;
}

// ---------- резервный провайдер: ipwho.is (по одному IP, без батча) ----------
// Используется только когда ip-api.com не ответил после всех повторов —
// экономим лимит резервного провайдера на реально нештатные ситуации, а не
// дублируем каждый запрос дважды "на всякий случай".
async function geoFallbackRequestOne(ip) {
  try {
    const url = `https://ipwho.is/${encodeURIComponent(ip)}?fields=success,message,country_code,continent_code,latitude,longitude,city,ip`;
    const res = await fetchWithTimeout(url, {}, GEOIP_FALLBACK_TIMEOUT_MS);
    if (!res.ok) return null;
    const data = await res.json();
    if (!data || data.success === false) return null;
    return {
      status: 'success',
      query: data.ip || ip,
      countryCode: data.country_code || null,
      continentCode: data.continent_code || null,
      lat: typeof data.latitude === 'number' ? data.latitude : null,
      lon: typeof data.longitude === 'number' ? data.longitude : null,
      city: data.city || null,
    };
  } catch (e) {
    console.warn(`[geoip-fallback] ipwho.is — ошибка для ${ip}: ${e.message}`);
    return null;
  }
}

async function geoFallbackRequest(ips) {
  const results = [];
  let i = 0;
  async function worker() {
    while (i < ips.length) {
      const idx = i++;
      const item = await geoFallbackRequestOne(ips[idx]);
      if (item) results.push(item);
    }
  }
  await Promise.all(Array.from({ length: Math.min(GEOIP_FALLBACK_CONCURRENCY, ips.length) }, worker));
  return results;
}

// Определяет бакет региона (ru/us/asia/eu) по коду страны + континента.
export function mapCountryToBucket(countryCode, continentCode) {
  if (!countryCode) return null;
  if (RU_BUCKET_COUNTRIES.has(countryCode)) return 'ru';
  if (US_BUCKET_COUNTRIES.has(countryCode)) return 'us';
  if (continentCode === 'AS') return 'asia';
  return 'eu'; // Европа/Африка/Юж.Америка/Океания — тот же дефолт, что и раньше
}

// Геолоцирует список IP. Возвращает Map ip -> { countryCode, continentCode,
// region, lat, lon, city }. lat/lon — для сортировки прокси по расстоянию
// до посетителя (гаверсинус), а не по буквальному совпадению города —
// геолокация дата-центровых IP по городу сама по себе не точна, поэтому
// city здесь чисто справочное поле (для админки/отладки), а не критерий
// фильтрации.
// Кэш на диске переиспользуется между прогонами, чтобы не тратить лимит
// ip-api.com на одни и те же IP каждые 40 минут.
export async function geolocateIps(ips) {
  const uniqueIps = Array.from(new Set(ips.filter(Boolean)));
  const diskCache = await loadDiskCache();
  const now = Date.now();

  const result = new Map();
  const toQuery = [];

  const pickFields = (src) => ({
    countryCode: src.countryCode, continentCode: src.continentCode, region: src.region,
    lat: typeof src.lat === 'number' ? src.lat : null,
    lon: typeof src.lon === 'number' ? src.lon : null,
    city: src.city || null,
  });

  for (const ip of uniqueIps) {
    const cached = diskCache[ip];
    if (cached && now - cached.fetchedAt < GEOIP_CACHE_TTL_MS) {
      result.set(ip, pickFields(cached));
    } else {
      toQuery.push(ip);
    }
  }

  console.log(`[geoip] уникальных ip: ${uniqueIps.length}, из кэша: ${uniqueIps.length - toQuery.length}, запросить: ${toQuery.length}`);

  for (let offset = 0; offset < toQuery.length; offset += GEOIP_BATCH_SIZE) {
    const chunk = toQuery.slice(offset, offset + GEOIP_BATCH_SIZE);
    let items = await geoBatchRequestWithRetry(chunk);
    let source = 'ip-api.com';
    if (items === null) {
      console.warn(`[geoip] ip-api.com недоступен после ${GEOIP_MAX_RETRIES + 1} попыток — переключаюсь на резервный провайдер (ipwho.is) для ${chunk.length} ip`);
      items = await geoFallbackRequest(chunk);
      source = 'ipwho.is';
    }
    for (const item of items) {
      if (!item || item.status !== 'success' || !item.query) continue;
      const region = mapCountryToBucket(item.countryCode, item.continentCode);
      const entry = {
        countryCode: item.countryCode || null,
        continentCode: item.continentCode || null,
        region,
        lat: typeof item.lat === 'number' ? item.lat : null,
        lon: typeof item.lon === 'number' ? item.lon : null,
        city: item.city || null,
        source,
      };
      result.set(item.query, pickFields(entry));
      diskCache[item.query] = { ...entry, fetchedAt: now };
    }
    if (offset + GEOIP_BATCH_SIZE < toQuery.length) await sleep(GEOIP_BATCH_DELAY_MS);
  }

  const removedCount = pruneExpiredCache(diskCache, now);
  if (removedCount > 0) {
    console.log(`[geoip] кэш: удалено ${removedCount} устаревших записей (старше ${Math.round(GEOIP_CACHE_TTL_MS / 86400000)} дней), осталось ${Object.keys(diskCache).length}`);
  }
  await saveDiskCache(diskCache);
  return result;
}

// Читает уже накопленный дисковый кэш (data/geoip-cache.json) БЕЗ единого
// сетевого запроса. Используется в collect.js, чтобы бесплатно подставить
// уже известный регион новым кандидатам, если их IP уже встречался в
// предыдущих прогонах check.js — отсутствующие в кэше IP просто не попадают
// в результат (вызывающий код сам решает, что делать с ними дальше — в
// collect.js это эвристика по домену, как и раньше).
export async function peekCachedGeo(ips) {
  const diskCache = await loadDiskCache();
  const now = Date.now();
  const result = new Map();
  for (const ip of new Set(ips.filter(Boolean))) {
    const cached = diskCache[ip];
    if (cached && now - cached.fetchedAt < GEOIP_CACHE_TTL_MS) {
      result.set(ip, {
        countryCode: cached.countryCode, continentCode: cached.continentCode, region: cached.region,
        lat: typeof cached.lat === 'number' ? cached.lat : null,
        lon: typeof cached.lon === 'number' ? cached.lon : null,
        city: cached.city || null,
      });
    }
  }
  return result;
}
