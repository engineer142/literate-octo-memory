// geoip-client.js
//
// Геолокация IP ПОСЕТИТЕЛЯ сайта (не прокси — прокси гео-лоцируются
// отдельно, в proxy-sync/scripts/lib/geoip.js, батчем раз в 40 минут).
// Здесь всё иначе:
//   - по одному IP за раз (запрос приходит в реальном времени на каждый
//     визит, батчить нечего);
//   - используется ОДИН И ТОТ ЖЕ IP от одного посетителя МНОГО раз подряд
//     (перезагрузки страницы, повторные визиты в течение дня) — поэтому
//     здесь свой in-memory кэш (через cache.js, уже используется в
//     server.js для Firestore-ответов), а не общий с прокси-геолокацией.
//
// ВАЖНО: этот VPS "в серую" (см. README.md, DNS без Cloudflare edge), то
// есть здесь НЕТ request.cf с готовым city/latitude/longitude, как было бы
// на Cloudflare Worker — IP посетителя нужно гео-лоцировать самим, тем же
// способом, что и прокси.
//
// ip-api.com бесплатный тариф — только HTTP (не HTTPS), без ключа,
// 45 запросов/мин. Кэш держит нагрузку в разумных пределах при обычном
// трафике сайта; если понадобится больше — можно перейти на платный план
// ip-api.com или локальную GeoIP-базу (MaxMind GeoLite2), не меняя
// остальной код (весь доступ — через geolocateVisitorIp ниже).
//
// Устойчивость к сбоям — короче, чем в proxy-sync/scripts/lib/geoip.js,
// потому что это хот-путь ЖИВОГО HTTP-запроса посетителя (он ждёт ответ
// прямо сейчас, а не фоновый батч раз в 40 минут):
//   - 1 доп. попытка к ip-api.com (VISITOR_GEOIP_MAX_RETRIES), задержка
//     между попытками капается VISITOR_GEOIP_RETRY_MAX_DELAY_MS даже если
//     сервер прислал больший Retry-After — секунды ожидания на 429 не
//     годятся для одного HTTP-ответа;
//   - если и повтор не помог — резервный провайдер ipwho.is (HTTPS, тоже
//     бесплатный без ключа), один запрос;
//   - неудачный результат (оба провайдера недоступны) кэшируется
//     ненадолго (VISITOR_GEOIP_NEGATIVE_CACHE_SECONDS, 5 мин) — не на все
//     6 часов, что и удачный, — чтобы временный сбой не держал посетителя
//     без геолокации (а значит, без вкладки "Рядом") дольше необходимого.
//
// IP посетителя сюда передаётся УЖЕ извлечённым — server.js берёт его из
// req.ip (Express/proxy-addr, с app.set('trust proxy', 'loopback')), а не
// самодельным разбором X-Forwarded-For. Это важно: наивный разбор вида
// "взять первое значение из заголовка" небезопасен — посетитель мог сам
// вписать в X-Forwarded-For что угодно, а nginx (см. README.md) лишь
// дописывает свой $remote_addr — в зависимости от конфига либо в конец
// (и тогда "первое значение" — это подделанное посетителем), либо
// перезаписывает целиком. proxy-addr с 'loopback' корректно вычисляет
// реальный IP независимо от этого — идёт по цепочке справа налево и
// останавливается на первом НЕ-loopback адресе.

import { cacheGet, cacheSet } from './cache.js';

const FETCH_TIMEOUT_MS = Number(process.env.VISITOR_GEOIP_TIMEOUT_MS || 3000);
const VISITOR_GEOIP_CACHE_SECONDS = Number(process.env.VISITOR_GEOIP_CACHE_SECONDS || 6 * 60 * 60); // 6ч — успешный результат
const VISITOR_GEOIP_NEGATIVE_CACHE_SECONDS = Number(process.env.VISITOR_GEOIP_NEGATIVE_CACHE_SECONDS || 5 * 60); // 5мин — оба провайдера недоступны
const VISITOR_GEOIP_MAX_RETRIES = Number(process.env.VISITOR_GEOIP_MAX_RETRIES || 1); // доп. попытки к ip-api.com, не считая первой
const VISITOR_GEOIP_RETRY_BASE_DELAY_MS = Number(process.env.VISITOR_GEOIP_RETRY_BASE_DELAY_MS || 400);
const VISITOR_GEOIP_RETRY_MAX_DELAY_MS = Number(process.env.VISITOR_GEOIP_RETRY_MAX_DELAY_MS || 1000); // потолок задержки даже если Retry-After больше
const VISITOR_GEOIP_FALLBACK_TIMEOUT_MS = Number(process.env.VISITOR_GEOIP_FALLBACK_TIMEOUT_MS || 3000);

// Те же бакеты, что в proxy-sync/scripts/lib/geoip.js (mapCountryToBucket) —
// ДЕРЖАТЬ В СИНХРОНЕ РУКАМИ при изменении одного из двух мест: это два
// независимых репозитория (GitHub Actions job и VPS-сервис), общего
// npm-пакета между ними нет.
const RU_BUCKET_COUNTRIES = new Set(['RU', 'BY', 'KZ', 'KG', 'TJ', 'TM', 'UZ', 'IR', 'AM', 'AZ', 'GE', 'MD']);
const US_BUCKET_COUNTRIES = new Set(['US', 'CA', 'MX']);

export function mapCountryToBucket(countryCode, continentCode) {
  if (!countryCode) return null;
  if (RU_BUCKET_COUNTRIES.has(countryCode)) return 'ru';
  if (US_BUCKET_COUNTRIES.has(countryCode)) return 'us';
  if (continentCode === 'AS') return 'asia';
  return 'eu';
}

// Приватные/локальные адреса гео-лоцировать бессмысленно (например,
// разработка локально, или если nginx вдруг не проставил X-Forwarded-For
// и достался req.socket.remoteAddress контейнера/локалхоста).
function isPrivateOrLocalIp(ip) {
  if (!ip) return true;
  if (ip === '127.0.0.1' || ip === '::1') return true;
  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
  if (/^::ffff:127\./.test(ip)) return true;
  // IPv6: fc00::/7 (unique local, RFC 4193) и fe80::/10 (link-local) —
  // на практике сюда не должны долетать (сайт публичный, IPv4), но на
  // всякий случай, чтобы не тратить запрос к geoIP-провайдеру впустую.
  if (/^f[cd][0-9a-f]{2}:/i.test(ip)) return true;
  if (/^fe[89ab][0-9a-f]:/i.test(ip)) return true;
  return false;
}

// Express/proxy-addr иногда отдаёt IPv4 в виде IPv4-mapped IPv6
// ("::ffff:1.2.3.4") — geoIP-провайдеры такой формат не всегда понимают
// (ip-api.com и ipwho.is ожидают чистый IPv4/IPv6). Снимаем префикс перед
// тем, как передавать IP дальше в geolocateVisitorIp.
export function normalizeIp(ip) {
  if (!ip) return ip;
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
  return m ? m[1] : ip;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(t);
  }
}

// ---------- основной провайдер: ip-api.com (по одному IP) ----------

// Один запрос. Возвращает { normalized, retryAfterSeconds }:
//   normalized === null — не удалось (сеть/таймаут/HTTP-ошибка/429/status!=='success')
//   normalized === {...} — унифицированная форма, общая с резервным провайдером ниже
async function primaryRequestOnce(ip) {
  const fields = 'status,message,countryCode,continentCode,lat,lon,city,query';
  const url = 'http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=' + fields;
  try {
    const res = await fetchWithTimeout(url, FETCH_TIMEOUT_MS);
    if (res.status === 429) {
      const h = res.headers && typeof res.headers.get === 'function' ? res.headers.get('retry-after') : null;
      const retryAfterSeconds = h ? Number(h) : null;
      console.warn('[geoip-client] ip-api.com — 429 (рейт-лимит)' + (retryAfterSeconds ? `, retry-after=${retryAfterSeconds}с` : ''));
      return { normalized: null, retryAfterSeconds: Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : null };
    }
    if (!res.ok) {
      console.warn(`[geoip-client] ip-api.com — HTTP ${res.status}`);
      return { normalized: null, retryAfterSeconds: null };
    }
    const data = await res.json();
    if (!data || data.status !== 'success') return { normalized: null, retryAfterSeconds: null };
    return {
      normalized: {
        query: data.query || ip,
        countryCode: data.countryCode || null,
        continentCode: data.continentCode || null,
        lat: typeof data.lat === 'number' ? data.lat : null,
        lon: typeof data.lon === 'number' ? data.lon : null,
        city: data.city || null,
      },
      retryAfterSeconds: null,
    };
  } catch (e) {
    console.warn('[geoip-client] ip-api.com — ошибка: ' + e.message);
    return { normalized: null, retryAfterSeconds: null };
  }
}

// До VISITOR_GEOIP_MAX_RETRIES доп. попыток. В отличие от батч-версии в
// proxy-sync/scripts/lib/geoip.js задержка между попытками ЖЁСТКО
// капается VISITOR_GEOIP_RETRY_MAX_DELAY_MS, даже если сервер прислал
// больший Retry-After — это хот-путь живого запроса посетителя, а не
// фоновая задача, ждать несколько секунд ради одного HTTP-ответа нельзя.
async function primaryRequestWithRetry(ip) {
  for (let attempt = 0; attempt <= VISITOR_GEOIP_MAX_RETRIES; attempt++) {
    const { normalized, retryAfterSeconds } = await primaryRequestOnce(ip);
    if (normalized) return normalized;
    if (attempt === VISITOR_GEOIP_MAX_RETRIES) break;
    const delayMs = Math.min(
      retryAfterSeconds != null ? retryAfterSeconds * 1000 : VISITOR_GEOIP_RETRY_BASE_DELAY_MS * 2 ** attempt,
      VISITOR_GEOIP_RETRY_MAX_DELAY_MS
    );
    await sleep(delayMs);
  }
  return null;
}

// ---------- резервный провайдер: ipwho.is ----------
// Только когда ip-api.com не ответил после всех повторов — не дублируем
// каждый запрос дважды "на всякий случай", экономим лимит резерва на
// реально нештатные ситуации.
async function fallbackRequest(ip) {
  try {
    const url = `https://ipwho.is/${encodeURIComponent(ip)}?fields=success,message,country_code,continent_code,latitude,longitude,city,ip`;
    const res = await fetchWithTimeout(url, VISITOR_GEOIP_FALLBACK_TIMEOUT_MS);
    if (!res.ok) return null;
    const data = await res.json();
    if (!data || data.success === false) return null;
    return {
      query: data.ip || ip,
      countryCode: data.country_code || null,
      continentCode: data.continent_code || null,
      lat: typeof data.latitude === 'number' ? data.latitude : null,
      lon: typeof data.longitude === 'number' ? data.longitude : null,
      city: data.city || null,
    };
  } catch (e) {
    console.warn(`[geoip-client] ipwho.is (резерв) — ошибка для ${ip}: ${e.message}`);
    return null;
  }
}

// Возвращает { ip, countryCode, continentCode, region, lat, lon, city } | null.
// null — IP приватный/локальный, либо гео-лоцировать не удалось на обоих
// провайдерах (сеть, таймаут, рейт-лимит) — в этом случае вызывающий код
// (роут /servers/nearby) должен упасть на фоллбэк по региону или просто на
// общий список, а не отдать ошибку посетителю.
export async function geolocateVisitorIp(ip) {
  if (isPrivateOrLocalIp(ip)) return null;

  const cacheKey = 'visitor-geo:' + ip;
  // cache.js не различает "ключа нет" и "закэшировано null" — оба случая
  // cacheGet возвращает null. Для негативного кэша (см. выше) это
  // критично: без обёртки провал геолокации никогда бы не кэшировался на
  // самом деле — каждый следующий визит с того же IP снова бы дёргал
  // обоих провайдеров, а не ждал VISITOR_GEOIP_NEGATIVE_CACHE_SECONDS.
  // Оборачиваем значение в { v: ... }, чтобы наличие самой обёртки было
  // однозначным признаком "уже проверяли" — даже когда v === null.
  const cached = cacheGet(cacheKey);
  if (cached) return cached.v; // включая закэшированный null (не плодим повторные запросы на время негативного TTL)

  let normalized = await primaryRequestWithRetry(ip);
  if (!normalized) {
    console.warn(`[geoip-client] ip-api.com недоступен после ${VISITOR_GEOIP_MAX_RETRIES + 1} попыток — пробую резервный провайдер (ipwho.is) для ${ip}`);
    normalized = await fallbackRequest(ip);
  }

  const result = normalized
    ? {
        ip: normalized.query,
        countryCode: normalized.countryCode,
        continentCode: normalized.continentCode,
        region: mapCountryToBucket(normalized.countryCode, normalized.continentCode),
        lat: normalized.lat,
        lon: normalized.lon,
        city: normalized.city,
      }
    : null;

  cacheSet(cacheKey, { v: result }, result ? VISITOR_GEOIP_CACHE_SECONDS : VISITOR_GEOIP_NEGATIVE_CACHE_SECONDS);
  return result;
}
