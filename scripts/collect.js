// scripts/collect.js
//
// Сбор кандидатов MTProto-прокси из публичных источников.
// Порт логики COLLECT_* / collectParseCandidates / collectDetectRegion
// из bogestv0-mtproto-checker/worker.js — БЕЗ чанкования по тикам:
// в GitHub Actions нет лимита "50 подзапросов за вызов" и жёсткого
// CPU-таймаута, поэтому все источники обходятся за один прогон.
//
// Результат: data/candidates.json — плоский массив
//   [{ host, port, secret, region }, ...]
// Файл — вход для scripts/check.js (проверка живости).
//
// region для НОВЫХ кандидатов изначально ставится эвристикой по домену
// (collectDetectRegion) — как и раньше, — но перед записью в
// candidates.json сверяется с уже накопленным GeoIP-кэшем
// (data/geoip-cache.json, наполняется check.js): если IP этого хоста уже
// когда-то гео-лоцировался (тот же сервер под другим портом/секретом,
// или просто уже проверялся раньше), регион берётся оттуда — БЕЗ единого
// нового сетевого запроса к ip-api.com/ipwho.is, только чтение файла +
// DNS-резолв (дешёво). Кандидаты, чьих IP ещё нет в кэше, получат точный
// регион позже — на стадии check.js, когда для них в принципе будет
// делаться "живой" запрос к geoIP. Так GitHub Actions job не тратит
// лимит geoIP-провайдеров на кандидатов, которые почти наверняка мертвы
// (типичный collect: тысячи новых, живых — единицы процентов).
// Выключается переменной COLLECT_GEOIP=off (тогда остаётся чистая
// эвристика по домену, как было до этого апдейта).
//
// Запуск: node scripts/collect.js

import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { resolveHosts, peekCachedGeo } from './lib/geoip.js';

const COLLECT_GEOIP_ENABLED = process.env.COLLECT_GEOIP !== 'off';

// ---------- Источники (см. пометку в оригинале про приоритет первых) ----------
const COLLECT_SOURCES = [
  'https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt',
  'https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies.txt',
  'https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_all_verified.txt',
  'https://raw.githubusercontent.com/Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_all_tme_verified.txt',
  'https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_eu.txt',
  'https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt',
  'https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/master/all_proxies.txt',
  'https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt',
  'https://mtpro.xyz/api/?type=mtproto',
  'https://mtpro.xyz/api/?type=mtproto-ru',
  'https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.txt',
  'https://raw.githubusercontent.com/Freedom-Guard/Proxy/main/proxies/mtproto.txt',
  'https://raw.githubusercontent.com/securemanager/MTPROTO/main/proxies.txt',
  'https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/mtproto_proxies.txt',
  'https://raw.githubusercontent.com/seriyps/mtproto_proxy/master/proxies.txt',
  'https://raw.githubusercontent.com/MTProto/MTProtoProxy/master/proxies/mtproto.txt',
  'https://raw.githubusercontent.com/mtProtoProxy/MTProxy-official/master/proxies.txt',
  'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no1.txt',
  'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no2.txt',
  'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no3.txt',
  'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no4.txt',
  'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no5.txt',
  'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no6.txt',
  'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no7.txt',
  'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no8.txt',
  'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no9.txt',
  'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB/refs/heads/main/telegram_proxy_no10.txt',
  'https://raw.githubusercontent.com/iwh3n/tg-proxy/refs/heads/main/proxys/All_Proxys.txt',
  'https://raw.githubusercontent.com/kubiknubika/my-tg-proxies/refs/heads/main/data/proxies.json',
  'https://raw.githubusercontent.com/shablin/mtproto-proxy/refs/heads/main/data/valid_proxy.json',
  'https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/protocols/mtproto.txt',
  'https://raw.githubusercontent.com/helptmoop/Free-Telegram-Proxies/refs/heads/main/global-iran-russia-proxies.txt',
  'https://raw.githubusercontent.com/helptmoop/Free-Telegram-Proxies/refs/heads/main/turkmenistan-global-iran-russia.txt',
  'https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt',
  'https://raw.githubusercontent.com/McDaived/ProxyDaiv/refs/heads/main/public/proxies.json',
  'https://raw.githubusercontent.com/klondike0x/mtp4tg-proxies/refs/heads/main/all_proxies.txt',
  'https://raw.githubusercontent.com/weltimistar777-crypto/MTProxy/refs/heads/main/proxy.txt',
  'https://raw.githubusercontent.com/Airuop/MTProtoCollector/refs/heads/main/proxy/mtproto.json',
  'https://raw.githubusercontent.com/blog1703/tgonline/refs/heads/main/proxies.txt',
  'https://moonlunavpn.com/proxies.txt',
  'https://moonlunavpn.com/proxies.json',
];

const COLLECT_RU_DOMAINS = [
  '.ru', 'yandex', 'vk.com', 'mail.ru', 'ok.ru', 'dzen', 'rutube', 'sber', 'tinkoff', 'vtb',
  'gosuslugi', 'nalog', 'mos.ru', 'ozon', 'wildberries', 'avito', 'kinopoisk', 'mts', 'beeline',
  '.ir', 'aparat.com', 'digikala.com', 'irancell.ir', 'mci.ir',
];
const COLLECT_US_DOMAINS = [
  '.us', '.nyc', '.la', '.sf', '.dallas', '.gov',
  'amazonaws.com', 'digitalocean.com', 'cloudflare.com',
  'google.com', 'googlevideo.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
  'microsoft.com', 'msn.com', 'live.com', 'bing.com', 'windows.net', 'office.com', 'azureedge.net',
  'apple.com', 'icloud.com',
  'akamai.net', 'akamaihd.net', 'akamaized.net',
  'fastly.net',
];
const COLLECT_ASIA_DOMAINS = ['.asia', '.jp', '.cn', '.sg', '.hk', '.kr', '.in', '.tw', '.ph', '.my', '.id', '.vn', '.th'];
const COLLECT_BLOCKED = ['instagram', 'facebook', 'twitter', 'bbc', 'meduza', 'linkedin', 'torproject'];

// В Worker'е было 500 из-за лимита подзапросов. В Actions лимита нет —
// потолок теперь чисто предохранитель на случай аномалии в источниках,
// а не реальное ограничение (реальных публичных MTProto-серверов в разы
// меньше этого числа).
const COLLECT_MAX_CANDIDATES = Number(process.env.COLLECT_MAX_CANDIDATES || 20000);
const FETCH_TIMEOUT_MS = 15000;
const FETCH_CONCURRENCY = 10;

// ---------- Telegram-каналы: публичные t.me/s/<channel> страницы ----------
// Не требует Bot API токена — t.me/s/ отдаёт статичный HTML с последними
// постами публично, без авторизации. Каналы, которые регулярно публикуют
// tg://proxy ссылки.
const TELEGRAM_PROXY_CHANNELS = [
  'proxy_mtproto',
  'MTProtoProxyChannel',
  'proxyfreetg',
  'mtprotoproxy_list',
  'proxymt24',
];

// ---------- Самопополняющийся список: GitHub Code Search ----------
// Ищет по всему GitHub код, содержащий "tg://proxy?server=" — новые репо
// с прокси-листами появляются сами по себе, без ручного добавления.
// Найденные raw-URL сохраняются в data/discovered-sources.json и на
// следующих прогонах подмешиваются к статичному списку COLLECT_SOURCES.
const GITHUB_CODE_SEARCH_QUERIES = [
  '"tg://proxy?server=" extension:txt',
  '"tg://proxy?server=" extension:json',
];
const DISCOVERED_SOURCES_PATH = 'data/discovered-sources.json';
const MAX_DISCOVERED_SOURCES = 300; // предохранитель, чтобы список не рос бесконечно

// ---------- Самопополнение: НОВЫЕ Telegram-каналы ----------
// Та же идея, что и с GitHub Code Search выше, но источник упоминаний —
// сами уже известные каналы/источники: такие каналы почти всегда
// упоминают "дружественные"/рекламные/сетевые каналы (see "@..." в
// подписи поста, "More: @...", "Ads: @...", "Related channels" и т.п.).
// Вместо того чтобы искать по всему Telegram (публичного API для этого
// без бот-токена/MTProto-клиента нет), мы просто вылавливаем ВСЕ "@handle"
// упоминания из уже скачанного текста (HTML каналов + содержимое
// GitHub-источников), для новых — реально проверяем t.me/s/<handle> на
// наличие хотя бы одного разбираемого прокси-кандидата, и только тогда
// добавляем в копилку. Отклонённые (не прокси-каналы) запоминаются
// отдельно, чтобы не проверять их заново каждый прогон.
const DISCOVERED_CHANNELS_PATH = 'data/discovered-channels.json';
const MAX_DISCOVERED_CHANNELS = 60; // каналов кандидатов немного, держим лимит скромнее GitHub-источников
const MAX_NEW_CHANNEL_CHECKS_PER_RUN = 15; // не устраивать лавину новых t.me/s/ запросов за один прогон
// ДОБАВЛЕНО: раньше канал, однажды попавший в discovered.channels,
// проверялся КАЖДЫЙ прогон НАВСЕГДА, даже если давно перестал постить
// прокси (0 кандидатов много прогонов подряд подряд) — впустую тратили
// запрос на мёртвый/уснувший канал каждые 40 минут. Теперь считаем
// emptyStreak (сколько прогонов подряд канал отдал 0 кандидатов) и, если
// он превышает порог — "усыпляем" канал: убираем из активного списка
// (но НЕ в rejected — rejected окончательный и не пересматривается; тут
// же канал просто перестаёт быть "известным", и если он всплывёт в
// чьём-то упоминании позже и снова начнёт постить прокси — его найдут и
// проверят заново как нового кандидата, см. discoverNewChannels).
// MAX_DISCOVERED_CHANNELS_EMPTY_STREAK=6 при цикле в 40 минут — это
// примерно 4 часа полного молчания подряд, прежде чем канал уснёт.
const MAX_CHANNEL_EMPTY_STREAK = Number(process.env.MAX_CHANNEL_EMPTY_STREAK || 6);
// Официальные правила Telegram: username 5-32 символов, начинается с буквы.
const CHANNEL_MENTION_RE = /@([A-Za-z][A-Za-z0-9_]{4,31})/g;
// Явный мусор: рекламные/донат/бот-аккаунты, которые часто мелькают в
// подписях таких постов, но точно не являются каналами-источниками прокси.
const CHANNEL_MENTION_BLOCKLIST = new Set([
  'telegram', 'durov', 'contactmtproxybot', 'mtproxybot', 'proxymadata',
]);


function collectIsBlocked(secret, domain) {
  if (!secret || secret.length < 16) return true;
  if (!domain) return false;
  return COLLECT_BLOCKED.some((b) => domain.indexOf(b) !== -1);
}

function collectDetectRegion(domain) {
  if (!domain) return 'eu';
  const d = domain.toLowerCase();
  if (COLLECT_RU_DOMAINS.some((m) => d.indexOf(m) !== -1)) return 'ru';
  if (COLLECT_US_DOMAINS.some((m) => d.indexOf(m) !== -1)) return 'us';
  if (COLLECT_ASIA_DOMAINS.some((m) => d.indexOf(m) !== -1)) return 'asia';
  return 'eu';
}

// Декодирует домен маскировки из MTProto-секрета формата "ee..." (ADTLS).
function collectDecodeDomain(secret) {
  if (!secret || secret.slice(0, 2).toLowerCase() !== 'ee') return null;
  try {
    const chars = [];
    for (let i = 2; i < secret.length - 1; i += 2) {
      const v = parseInt(secret.slice(i, i + 2), 16);
      if (!v) break;
      if (v >= 32 && v <= 126) chars.push(String.fromCharCode(v));
    }
    const out = chars.join('').toLowerCase();
    return out || null;
  } catch {
    return null;
  }
}

function collectValidPort(p) {
  const n = parseInt(p, 10);
  return n >= 1 && n <= 65535;
}

// Портировано из collectParseCandidates (worker.js) — только ветки,
// дающие MTProto-кандидатов (host, port, secret).
function collectParseCandidates(text) {
  const out = new Map(); // key host:port:secret -> {host, port, secret}
  function add(host, port, secret) {
    if (!collectValidPort(port) || !host || !secret) return;
    const key = `${host}:${port}:${secret}`;
    if (!out.has(key)) out.set(key, { host: String(host), port: parseInt(port, 10), secret: String(secret) });
  }

  const re1 = /tg:\/\/proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)/gi;
  let m;
  while ((m = re1.exec(text))) add(decodeURIComponent(m[1]), m[2], m[3]);

  const re2 = /t\.me\/proxy\?server=([^&\s]+)&port=(\d+)&secret=([A-Za-z0-9_=+/%-]+)/gi;
  while ((m = re2.exec(text))) add(decodeURIComponent(m[1]), m[2], m[3]);

  const re3 = /([A-Za-z0-9.-]+):(\d+):([A-Fa-f0-9]{16,})/g;
  while ((m = re3.exec(text))) add(m[1], m[2], m[3]);

  // ДОБАВЛЕНО: некоторые каналы (напр. proxymt24 и похожие) публикуют
  // не ссылку, а обычный подписанный текст вида
  // "Server: xxx.example.com Port: 443 Secret: ee1603...", часто в 3
  // отдельных строках. \s* между полями съедает и переводы строк.
  // "Server: Unknown" пропускаем — это значит, что настоящий адрес не
  // раскрыт в тексте (только внутри кнопки-ссылки), а ссылку и так уже
  // ловят re1/re2 выше, если она реально есть в HTML.
  const re4 = /Server:\s*([A-Za-z0-9][A-Za-z0-9.-]*)\s*Port:\s*(\d+)\s*Secret:\s*([A-Fa-f0-9]{16,})/gi;
  while ((m = re4.exec(text))) {
    if (m[1].toLowerCase() === 'unknown') continue;
    add(m[1], m[2], m[3]);
  }

  const trimmed = text.trim();
  if (trimmed[0] === '[' || trimmed[0] === '{') {
    try {
      const data = JSON.parse(trimmed);
      const items = Array.isArray(data) ? data : [data];
      items.forEach((item) => {
        if (item && typeof item === 'object' && item.host && item.port && item.secret) {
          add(item.host, String(item.port), String(item.secret));
        }
      });
    } catch {
      /* не JSON — игнорируем */
    }
  }

  return Array.from(out.values());
}

async function fetchWithTimeout(url) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (proxy-sync collector)' },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    return await res.text();
  } catch (e) {
    console.warn(`[collect] ${url} — ошибка: ${e.message}`);
    return null;
  } finally {
    clearTimeout(t);
  }
}

// Извлекает tg://proxy / t.me/proxy ссылки прямо из HTML-страницы канала
// (t.me/s/<channel>) — та же регулярка, что и для обычных текстовых
// источников, просто применяется к HTML вместо .txt. Возвращает ещё и
// сырой html — он нужен discoverNewChannels() ниже, чтобы находить
// упоминания ДРУГИХ каналов в подписях постов этого канала.
async function fetchTelegramChannelCandidates(channel) {
  const url = `https://t.me/s/${channel}`;
  const html = await fetchWithTimeout(url);
  if (!html) {
    console.log(`[collect] t.me/s/${channel} — пропущен`);
    return { channel, candidates: [], html: '' };
  }
  const candidates = collectParseCandidates(html);
  console.log(`[collect] t.me/s/${channel} — ${candidates.length} кандидатов`);
  return { channel, candidates, html };
}

// ---------- GitHub Code Search: самопополнение списка источников ----------
async function githubCodeSearch(query) {
  const url = `https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=30`;
  const headers = {
    'User-Agent': 'proxy-sync-collector',
    Accept: 'application/vnd.github+json',
  };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

  try {
    const res = await fetch(url, { headers });
    if (!res.ok) {
      console.warn(`[collect] GitHub code search "${query}" — HTTP ${res.status}`);
      return [];
    }
    const data = await res.json();
    return Array.isArray(data.items) ? data.items : [];
  } catch (e) {
    console.warn(`[collect] GitHub code search "${query}" — ошибка: ${e.message}`);
    return [];
  }
}

// Превращает результат code search (repo/path/ref) в прямую raw-ссылку.
function githubItemToRawUrl(item) {
  if (!item || !item.repository || !item.repository.full_name || !item.path) return null;
  // code search не отдаёт ветку напрямую — default_branch не всегда есть
  // в укороченном объекте repository, поэтому используем HEAD, GitHub
  // сам резолвит его в дефолтную ветку для raw.githubusercontent.com.
  return `https://raw.githubusercontent.com/${item.repository.full_name}/HEAD/${item.path}`;
}

async function discoverNewSources(existingSources, previouslyDiscovered) {
  const known = new Set([...existingSources, ...previouslyDiscovered]);
  const discovered = new Set(previouslyDiscovered);

  for (const query of GITHUB_CODE_SEARCH_QUERIES) {
    const items = await githubCodeSearch(query);
    for (const item of items) {
      const rawUrl = githubItemToRawUrl(item);
      if (!rawUrl || known.has(rawUrl)) continue;
      known.add(rawUrl);
      discovered.add(rawUrl);
      if (discovered.size >= MAX_DISCOVERED_SOURCES) break;
    }
    if (discovered.size >= MAX_DISCOVERED_SOURCES) break;
  }

  const added = discovered.size - previouslyDiscovered.length;
  console.log(`[collect] GitHub code search: новых источников найдено ${added}, всего в копилке ${discovered.size}`);
  return Array.from(discovered);
}

async function loadPreviousDiscoveredSources() {
  try {
    const raw = await readFile(DISCOVERED_SOURCES_PATH, 'utf8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch {
    return []; // файла ещё нет — это нормально на первом прогоне
  }
}

async function loadDiscoveredChannelsState() {
  try {
    const raw = await readFile(DISCOVERED_CHANNELS_PATH, 'utf8');
    const data = JSON.parse(raw);
    // Обратная совместимость: раньше channels был плоским списком строк
    // (["telmtproto", ...]) — теперь это объекты {handle, emptyStreak},
    // чтобы отслеживать, сколько прогонов подряд канал молчит. Старые
    // записи-строки просто оборачиваем с emptyStreak:0.
    const rawChannels = Array.isArray(data.channels) ? data.channels : [];
    const channels = rawChannels.map((c) =>
      typeof c === 'string' ? { handle: c, emptyStreak: 0 } : { handle: c.handle, emptyStreak: c.emptyStreak || 0 }
    );
    return {
      channels,
      rejected: Array.isArray(data.rejected) ? data.rejected : [],
    };
  } catch {
    return { channels: [], rejected: [] }; // файла ещё нет — это нормально на первом прогоне
  }
}

// Вытаскивает уникальные "@handle" упоминания из произвольного текста
// (HTML канала или содержимое источника), приводит к нижнему регистру.
function extractChannelMentions(text) {
  const out = new Set();
  let m;
  CHANNEL_MENTION_RE.lastIndex = 0;
  while ((m = CHANNEL_MENTION_RE.exec(text))) out.add(m[1].toLowerCase());
  return out;
}

// ДОБАВЛЕНО: "усыпляет" ранее найденные каналы, которые давно перестали
// постить прокси, вместо того чтобы проверять их каждый прогон навсегда.
// candidateCountByHandle — Map<handle(lowercase), число кандидатов ИЗ
// ЭТОГО прогона> для каналов, которые реально проверялись в main().
function pruneDormantChannels(channels, candidateCountByHandle) {
  const kept = [];
  for (const c of channels) {
    const count = candidateCountByHandle.get(c.handle) ?? null;
    if (count === null) {
      // почему-то не проверялся в этом прогоне (не должно происходить в
      // норме) — оставляем как есть, не трогаем счётчик вслепую.
      kept.push(c);
      continue;
    }
    const emptyStreak = count > 0 ? 0 : c.emptyStreak + 1;
    if (emptyStreak >= MAX_CHANNEL_EMPTY_STREAK) {
      console.log(
        `[collect] 💤 @${c.handle} молчит ${emptyStreak} прогонов подряд — усыплён (убран из активного списка).`
      );
      continue; // не добавляем обратно — канал "забыт", но не в rejected
    }
    kept.push({ handle: c.handle, emptyStreak });
  }
  return kept;
}

// Ищет НОВЫЕ прокси-каналы среди упоминаний "@handle" в уже скачанных
// текстах (HTML известных каналов + содержимое GitHub-источников), сама
// проверяет каждого нового кандидата запросом t.me/s/<handle> — считаем
// каналом-источником, только если он реально отдаёт хотя бы один
// разбираемый прокси. Непроверенные/непрокси-каналы запоминаются в
// rejected, чтобы не долбить их заново каждый прогон впустую.
async function discoverNewChannels(existingChannels, state, mentionTexts) {
  const knownChannels = new Set([
    ...existingChannels.map((c) => c.toLowerCase()),
    ...state.channels.map((c) => c.handle.toLowerCase()),
  ]);
  const rejected = new Set(state.rejected.map((c) => c.toLowerCase()));
  const discovered = [...state.channels];

  const mentions = new Set();
  for (const text of mentionTexts) {
    if (!text) continue;
    for (const handle of extractChannelMentions(text)) mentions.add(handle);
  }

  const candidates = Array.from(mentions).filter(
    (h) => !knownChannels.has(h) && !rejected.has(h) && !CHANNEL_MENTION_BLOCKLIST.has(h)
  );

  console.log(`[collect] найдено уникальных упоминаний каналов: ${mentions.size}, из них новых кандидатов на проверку: ${candidates.length}`);

  let checked = 0;
  for (const handle of candidates) {
    if (checked >= MAX_NEW_CHANNEL_CHECKS_PER_RUN) {
      console.log(`[collect] лимит проверок новых каналов за прогон (${MAX_NEW_CHANNEL_CHECKS_PER_RUN}) достигнут, остальные — в следующий раз.`);
      break;
    }
    checked++;
    const { candidates: found } = await fetchTelegramChannelCandidates(handle);
    if (found.length > 0) {
      discovered.push({ handle, emptyStreak: 0 });
      console.log(`[collect] ✅ новый прокси-канал: @${handle} (${found.length} кандидатов)`);
      if (discovered.length >= MAX_DISCOVERED_CHANNELS) {
        console.log(`[collect] лимит MAX_DISCOVERED_CHANNELS (${MAX_DISCOVERED_CHANNELS}) достигнут.`);
        break;
      }
    } else {
      rejected.add(handle);
      console.log(`[collect] ❌ @${handle} — прокси не найдены, помечен как непрокси-канал.`);
    }
  }

  return { channels: Array.from(discovered), rejected: Array.from(rejected) };
}

// ---------- Персистентность: не терять живые прокси между прогонами ----------
// Если источник временно не отдал строку с сервером, который на самом деле
// всё ещё жив, он не должен пропадать из выдачи — подмешиваем живых из
// прошлого прогона обратно в кандидаты на перепроверку.
async function loadPreviouslyAliveCandidates() {
  try {
    const raw = await readFile('data/checked.json', 'utf8');
    const data = JSON.parse(raw);
    if (!Array.isArray(data)) return [];
    return data
      .filter((c) => c.alive)
      .map((c) => ({ host: c.host, port: c.port, secret: c.secret, region: c.region, source: c.source || null }));
  } catch {
    return []; // файла ещё нет — это нормально на первом прогоне
  }
}

// Простой пул с ограниченной конкурентностью (аналог runWithConcurrency в worker.js)
async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let i = 0;
  async function worker() {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await fn(items[idx], idx);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

async function main() {
  const previouslyDiscovered = await loadPreviousDiscoveredSources();
  const newDiscovered = await discoverNewSources(COLLECT_SOURCES, previouslyDiscovered);
  await mkdir('data', { recursive: true });
  await writeFile(DISCOVERED_SOURCES_PATH, JSON.stringify(newDiscovered, null, 2));

  const allSources = [...COLLECT_SOURCES, ...newDiscovered];
  console.log(`[collect] источников: ${allSources.length} (${COLLECT_SOURCES.length} статичных + ${newDiscovered.length} найденных)`);

  const texts = await mapWithConcurrency(allSources, FETCH_CONCURRENCY, async (url) => {
    const text = await fetchWithTimeout(url);
    console.log(`[collect] ${url} — ${text ? text.length + ' байт' : 'пропущен'}`);
    return text;
  });

  const seen = new Map(); // host:port:secret -> candidate

  // Живые из прошлого прогона идут первыми — они не потеряются, даже если
  // источники их временно не отдали, и всё равно попадут под COLLECT_MAX_CANDIDATES.
  const previouslyAlive = await loadPreviouslyAliveCandidates();
  console.log(`[collect] живых из прошлого прогона (на перепроверку): ${previouslyAlive.length}`);
  for (const c of previouslyAlive) {
    seen.set(`${c.host}:${c.port}:${c.secret}`, c);
  }

  const channelState = await loadDiscoveredChannelsState();
  const discoveredHandles = channelState.channels.map((c) => c.handle);
  const allChannels = [...TELEGRAM_PROXY_CHANNELS, ...discoveredHandles];
  console.log(`[collect] каналов: ${allChannels.length} (${TELEGRAM_PROXY_CHANNELS.length} статичных + ${discoveredHandles.length} найденных ранее)`);

  const channelResults = await mapWithConcurrency(allChannels, FETCH_CONCURRENCY, (ch) =>
    fetchTelegramChannelCandidates(ch)
  );
  const rawCandidateLists = [
    ...channelResults.map((r) => ({ source: `tg:@${r.channel}`, candidates: r.candidates })),
    ...allSources.map((url, i) => ({ source: url, candidates: texts[i] ? collectParseCandidates(texts[i]) : [] })),
  ];

  // "Усыпляем" ранее найденные каналы, которые давно ничего не постят —
  // используем результаты фетча ИЗ ЭТОГО ЖЕ прогона (без лишних запросов).
  // Статичные каналы (TELEGRAM_PROXY_CHANNELS) сюда не попадают — они
  // заданы вручную и не усыпляются автоматически.
  const candidateCountByHandle = new Map(
    channelResults.map((r) => [r.channel.toLowerCase(), r.candidates.length])
  );
  channelState.channels = pruneDormantChannels(channelState.channels, candidateCountByHandle);

  // Самопополнение списка каналов: ищем "@handle" упоминания в текстах,
  // которые уже и так были скачаны на этом прогоне (HTML известных
  // каналов + содержимое обычных источников) — без единого лишнего
  // запроса, кроме проверки самих новых кандидатов.
  const newChannelState = await discoverNewChannels(
    TELEGRAM_PROXY_CHANNELS,
    channelState,
    [...channelResults.map((r) => r.html), ...texts]
  );
  await writeFile(DISCOVERED_CHANNELS_PATH, JSON.stringify(newChannelState, null, 2));

  const newKeys = []; // ключи, добавленные в ЭТОМ прогоне — только их сверяем с geoIP-кэшем ниже

  for (const { source, candidates } of rawCandidateLists) {
    for (const c of candidates) {
      const key = `${c.host}:${c.port}:${c.secret}`;
      if (seen.has(key)) continue;

      const domain = collectDecodeDomain(c.secret);
      if (collectIsBlocked(c.secret, domain)) continue;

      seen.set(key, {
        host: c.host,
        port: c.port,
        secret: c.secret,
        region: collectDetectRegion(domain),
        // ДОБАВЛЕНО: откуда взят этот кандидат (URL источника или
        // "tg:@channel") — нужно, чтобы потом оценивать НАДЁЖНОСТЬ
        // источника (какая доля кандидатов оттуда реально оказывается
        // живой), а не только километраж/пинг конкретного сервера.
        source,
      });
      newKeys.push(key);

      if (seen.size >= COLLECT_MAX_CANDIDATES) break;
    }
    if (seen.size >= COLLECT_MAX_CANDIDATES) break;
  }

  if (COLLECT_GEOIP_ENABLED && newKeys.length > 0) {
    const newHosts = newKeys.map((k) => seen.get(k).host);
    console.log(`[collect] geoip: сверяю ${new Set(newHosts).size} новых хостов с уже накопленным кэшем…`);
    const dnsCache = await resolveHosts(newHosts);
    const ips = Array.from(dnsCache.values()).filter(Boolean);
    const geoMap = await peekCachedGeo(ips);

    let upgraded = 0;
    for (const key of newKeys) {
      const entry = seen.get(key);
      const ip = dnsCache.get(entry.host);
      const geo = ip ? geoMap.get(ip) : null;
      if (geo && geo.region) {
        entry.region = geo.region; // перебиваем эвристику уже известным реальным регионом
        upgraded++;
      }
    }
    console.log(`[collect] geoip: регион подставлен из кэша у ${upgraded}/${newKeys.length} новых кандидатов (остальные получат его на стадии check.js)`);
  }

  const result = Array.from(seen.values());
  console.log(`[collect] итого уникальных кандидатов: ${result.length}`);

  await writeFile('data/candidates.json', JSON.stringify(result, null, 2));
  console.log('[collect] записано в data/candidates.json');
}

main().catch((e) => {
  console.error('[collect] фатальная ошибка:', e);
  process.exit(1);
});
