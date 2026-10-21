import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, '..');
const DATA_DIR = resolve(ROOT_DIR, 'data');
const SOURCES_DIR = resolve(ROOT_DIR, 'sources');

interface SourceDef {
  name: string;
  url: string;
  type: 'json-array' | 'json-obj' | 'metamask' | 'lines';
  defaultCategory?: string;
}

const SOURCES: SourceDef[] = [
  { name: 'Discord-AntiScam', url: 'https://raw.githubusercontent.com/Discord-AntiScam/scam-links/main/list.json', type: 'json-array', defaultCategory: 'discord-nitro' },
  { name: 'Sinking-Yachts', url: 'https://phish.sinking.yachts/v2/all', type: 'json-array', defaultCategory: 'discord-nitro' },
  { name: 'DaltonMenezes-Discord', url: 'https://raw.githubusercontent.com/daltonmenezes/discord-malicious-domains/main/domains/domains.json', type: 'json-array', defaultCategory: 'discord-nitro' },
  { name: 'nikolaischunk-domains', url: 'https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/domain-list.json', type: 'json-obj', defaultCategory: 'discord-nitro' },
  { name: 'nikolaischunk-suspicious', url: 'https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/suspicious-list.json', type: 'json-obj', defaultCategory: 'discord-nitro' },
  { name: 'nikolaischunk-txt', url: 'https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/domain-list.txt', type: 'lines', defaultCategory: 'discord-nitro' },
  { name: 'Dogino-scam-urls', url: 'https://raw.githubusercontent.com/Dogino/Discord-Phishing-URLs/main/scam-urls.txt', type: 'lines', defaultCategory: 'discord-nitro' },
  { name: 'Dogino-pihole', url: 'https://raw.githubusercontent.com/Dogino/Discord-Phishing-URLs/main/pihole-phishing-adlist.txt', type: 'lines', defaultCategory: 'discord-nitro' },
  { name: 'Andre601-AntiScam', url: 'https://raw.githubusercontent.com/Andre601/anti-scam-database/main/database/summary.json', type: 'json-array', defaultCategory: 'discord-nitro' },
  { name: 'ScamSniffer-Crypto', url: 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json', type: 'json-array', defaultCategory: 'crypto-drainer' },
  { name: 'MetaMask-Phishing', url: 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/config.json', type: 'metamask', defaultCategory: 'crypto-drainer' },
  { name: 'MetaMask-Hosts', url: 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/hosts.txt', type: 'lines', defaultCategory: 'crypto-drainer' },
  { name: 'URLhaus-Online', url: 'https://urlhaus.abuse.ch/downloads/text_online/', type: 'lines', defaultCategory: 'phishing-general' }
];

export const SHARED_HOSTING_SUFFIXES = new Set<string>([
  'pages.dev', 'workers.dev', 'vercel.app', 'netlify.app',
  'web.app', 'firebaseapp.com', 'github.io', 'gitlab.io',
  'onrender.com', 'render.com', 'glitch.me', 'replit.dev',
  'replit.app', 'repl.co', 'ngrok-free.app', 'ngrok.io',
  'ngrok.app', 'loca.lt', 'serveo.net', 'surge.sh',
  'fly.dev', 'railway.app', 'deno.dev', '000webhostapp.com',
  'pantheonsite.io', 'weebly.com', 'wixsite.com', 'blogspot.com'
]);

export function isDomainWhitelisted(domain: string, whitelist: Set<string>): boolean {
  if (whitelist.has(domain)) return true;

  const parts = domain.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join('.');

    // Shared hosting suffixes must not grant automatic wildcard immunity to scam subdomains
    if (SHARED_HOSTING_SUFFIXES.has(parent)) {
      continue;
    }

    if (whitelist.has(parent)) {
      return true;
    }
  }

  return false;
}

export function categorizeDomain(domain: string, fallback = 'phishing-general'): string {
  const d = domain.toLowerCase();
  if (/(?:nitro|glft|nltro|discor|dlscord|d1scord|discrod|discoord|discort|discorb|discocl|discqd|dlscqd|disscord|free.*gift|boost|hypesquad)/i.test(d)) return 'discord-nitro';
  if (/(?:steam|stean|stearn|tradeoffer|csgo|dota2|valv|tf2)/i.test(d)) return 'steam-trade';
  if (/(?:crypto|wallet|metamask|opensea|airdrop|phantom|solana|binance|coinbase|etherscan|uniswap|trustwallet|btc|eth|claim|drainer|web3|seaport|permit2|ledger|trezor|rabby|revoke|mint|presale|whitelist)/i.test(d)) return 'crypto-drainer';
  if (/(?:roblox|robux|rbx|roblx)/i.test(d)) return 'roblox-gaming';
  if (/(?:casino|gambling|bet|win|spin|jackpot|sedowin|wormwin|lenuwin)/i.test(d)) return 'casino-fraud';
  return fallback;
}

export async function fetchWhitelist(): Promise<Set<string>> {
  const set = new Set<string>();

  // 1. Local sources/whitelist.txt
  const localWhitelistPath = resolve(SOURCES_DIR, 'whitelist.txt');
  if (existsSync(localWhitelistPath)) {
    const lines = readFileSync(localWhitelistPath, 'utf8').split('\n');
    for (const l of lines) {
      const clean = l.trim().toLowerCase();
      if (clean && !clean.startsWith('#') && !clean.startsWith('//')) {
        set.add(clean);
      }
    }
  }

  // 2. Dogino official-domains.txt
  try {
    const res = await fetch('https://raw.githubusercontent.com/Dogino/Discord-Phishing-URLs/main/official-domains.txt', { signal: AbortSignal.timeout(10000) });
    if (res.ok) {
      const text = await res.text();
      for (const line of text.split('\n')) {
        const clean = line.trim().toLowerCase();
        if (clean && !clean.startsWith('#') && !clean.startsWith('//')) {
          set.add(clean);
        }
      }
    }
  } catch (err) {
    console.warn('Could not fetch Dogino official domains:', err);
  }

  // 3. High-reputation Top 10k (Tranco with OpenDNS fallback)
  try {
    console.log('Fetching Tranco top ranking list...');
    const metaRes = await fetch('https://tranco-list.eu/api/lists/date/latest', { signal: AbortSignal.timeout(8000) });
    if (metaRes.ok) {
      const meta = await metaRes.json() as { list_id?: string };
      if (meta.list_id) {
        const trancoRes = await fetch(`https://tranco-list.eu/download/${meta.list_id}/10000`, { signal: AbortSignal.timeout(15000) });
        if (trancoRes.ok) {
          const csv = await trancoRes.text();
          for (const line of csv.split('\n')) {
            const domain = line.split(',')[1]?.trim().toLowerCase();
            if (domain && domain.includes('.')) set.add(domain);
          }
        }
      }
    }
  } catch {
    console.warn('Tranco API unavailable, trying OpenDNS Top-10k fallback...');
    try {
      const openDnsRes = await fetch('https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt', { signal: AbortSignal.timeout(10000) });
      if (openDnsRes.ok) {
        const text = await openDnsRes.text();
        for (const line of text.split('\n')) {
          const domain = line.trim().toLowerCase();
          if (domain && domain.includes('.')) set.add(domain);
        }
      }
    } catch {
      console.warn('OpenDNS fallback also unavailable, using local baseline whitelist.');
    }
  }

  return set;
}

export async function buildDataset(): Promise<void> {
  const start = Date.now();
  console.log('Compiling comprehensive multi-source whitelist...');
  const officialSet = await fetchWhitelist();
  console.log(`Whitelist populated with ${officialSet.size} high-reputation and official domains.`);

  const domainMap = new Map<string, string>();
  let previousTotal = 0;

  // Pre-seed from existing data/all.json so known threats are never lost if an upstream vendor prunes or goes down
  const allJsonPath = resolve(DATA_DIR, 'all.json');
  if (existsSync(allJsonPath)) {
    try {
      const existing = JSON.parse(readFileSync(allJsonPath, 'utf8'));
      for (const [cat, list] of Object.entries(existing)) {
        if (Array.isArray(list)) {
          for (const d of list) {
            if (d && typeof d === 'string') {
              domainMap.set(d.toLowerCase(), cat);
              previousTotal++;
            }
          }
        }
      }
      console.log(`Pre-seeded ${domainMap.size} existing domains from current database.`);
    } catch (err) {
      console.warn('Could not read existing all.json, starting fresh:', err);
    }
  }

  for (const source of SOURCES) {
    console.log(`Fetching from ${source.name}...`);
    try {
      const res = await fetch(source.url, {
        headers: { 'User-Agent': 'fisphish-threat-sync/1.0 (+https://github.com/fisventurous/fisphish)' },
        signal: AbortSignal.timeout(25000)
      });
      if (!res.ok) {
        console.warn(`Failed to fetch ${source.name}: ${res.statusText}`);
        continue;
      }

      let entries: string[] = [];
      if (source.type === 'json-array') {
        const rawJson = await res.json() as unknown[];
        entries = rawJson.map(x => {
          if (typeof x === 'string') return x;
          if (x && typeof x === 'object' && 'domain' in x) return String((x as { domain: string }).domain);
          return '';
        }).filter(Boolean);
      } else if (source.type === 'json-obj') {
        const obj = await res.json() as { domains?: string[] };
        entries = obj.domains ?? [];
      } else if (source.type === 'metamask') {
        const obj = await res.json() as { blacklist?: string[] };
        entries = obj.blacklist ?? [];
      } else if (source.type === 'lines') {
        const text = await res.text();
        entries = text.split('\n');
      }

      for (const raw of entries) {
        let d = raw.toLowerCase().trim()
          .replace(/^https?:\/\//, '')
          .replace(/^www\./, '')
          .split('/')[0]!
          .split(':')[0]!;

        if (!d || !d.includes('.') || d.length > 120 || d.startsWith('.') || d.startsWith('#')) continue;
        if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(d)) continue;
        if (isDomainWhitelisted(d, officialSet)) continue;

        const cat = categorizeDomain(d, source.defaultCategory ?? 'phishing-general');
        const existing = domainMap.get(d);
        if (!existing || (existing === 'phishing-general' && cat !== 'phishing-general')) {
          domainMap.set(d, cat);
        }
      }
    } catch (err) {
      console.warn(`Error processing ${source.name}:`, err);
    }
  }

  // Ingest verified local custom sources
  const customFilePath = resolve(SOURCES_DIR, 'custom.txt');
  if (existsSync(customFilePath)) {
    console.log('Ingesting local verified custom domains...');
    const customText = readFileSync(customFilePath, 'utf8');
    for (const raw of customText.split('\n')) {
      let d = raw.toLowerCase().trim()
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '')
        .split('/')[0]!
        .split(':')[0]!;

      if (!d || !d.includes('.') || d.length > 120 || d.startsWith('.') || d.startsWith('#')) continue;
      if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(d)) continue;
      if (isDomainWhitelisted(d, officialSet)) continue;

      const cat = categorizeDomain(d, 'phishing-general');
      const existing = domainMap.get(d);
      if (!existing || (existing === 'phishing-general' && cat !== 'phishing-general')) {
        domainMap.set(d, cat);
      }
    }
  }

  // Scrub any domain matching the latest whitelist
  let scrubbedCount = 0;
  for (const domain of domainMap.keys()) {
    if (isDomainWhitelisted(domain, officialSet)) {
      domainMap.delete(domain);
      scrubbedCount++;
    }
  }
  if (scrubbedCount > 0) {
    console.log(`Purged ${scrubbedCount} whitelisted/official domains from threat list.`);
  }

  // Safety guard: ensure the database never drops significantly due to corrupted upstream feeds
  if (previousTotal > 0 && domainMap.size < (previousTotal - scrubbedCount)) {
    console.error(`Safety guard triggered: new domain count (${domainMap.size}) is lower than existing count (${previousTotal}). Aborting build to preserve dataset.`);
    process.exit(1);
  }

  const grouped: Record<string, string[]> = {
    'crypto-drainer': [],
    'discord-nitro': [],
    'steam-trade': [],
    'casino-fraud': [],
    'roblox-gaming': [],
    'phishing-general': []
  };

  for (const [domain, category] of domainMap.entries()) {
    if (!grouped[category]) grouped[category] = [];
    grouped[category].push(domain);
  }

  for (const key of Object.keys(grouped)) {
    grouped[key]!.sort();
  }

  if (!existsSync(DATA_DIR)) {
    mkdirSync(DATA_DIR, { recursive: true });
  }

  // 1. Grouped JSON (all.json)
  writeFileSync(allJsonPath, JSON.stringify(grouped, null, 2), 'utf8');

  // 2. Flat all domains list (domains.txt)
  const allDomains = Array.from(domainMap.keys()).sort();
  const domainsTxtPath = resolve(DATA_DIR, 'domains.txt');
  writeFileSync(domainsTxtPath, allDomains.join('\n') + '\n', 'utf8');

  // 3. Category split text files
  const categoryFiles: Record<string, string> = {
    'crypto-drainer': 'crypto-drainers.txt',
    'discord-nitro': 'discord-scams.txt',
    'steam-trade': 'steam-fraud.txt',
    'casino-fraud': 'casino-fraud.txt',
    'roblox-gaming': 'roblox-gaming.txt',
    'phishing-general': 'phishing-general.txt'
  };

  for (const [cat, filename] of Object.entries(categoryFiles)) {
    const list = grouped[cat] ?? [];
    const targetPath = resolve(DATA_DIR, filename);
    writeFileSync(targetPath, list.join('\n') + (list.length > 0 ? '\n' : ''), 'utf8');
  }

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`\nBuild complete in ${elapsed}s! Processed ${allDomains.length} unique domains.`);
  for (const [cat, list] of Object.entries(grouped)) {
    console.log(`  • ${cat}: ${list.length}`);
  }
}

if (process.argv[1] && (process.argv[1].endsWith('build.ts') || process.argv[1].endsWith('build.js'))) {
  buildDataset().catch(err => {
    console.error('Build failed:', err);
    process.exit(1);
  });
}
