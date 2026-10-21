import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, '..');
const DATA_DIR = resolve(ROOT_DIR, 'data');

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

export function categorizeDomain(domain: string, fallback = 'phishing-general'): string {
  const d = domain.toLowerCase();
  if (/(?:nitro|glft|nltro|discor|dlscord|d1scord|discrod|discoord|discort|discorb|discocl|discqd|dlscqd|disscord|free.*gift|boost|hypesquad)/i.test(d)) return 'discord-nitro';
  if (/(?:steam|stean|stearn|tradeoffer|csgo|dota2|valv|tf2)/i.test(d)) return 'steam-trade';
  if (/(?:crypto|wallet|metamask|opensea|airdrop|phantom|solana|binance|coinbase|etherscan|uniswap|trustwallet|btc|eth|claim|drainer|web3|seaport|permit2|ledger|trezor|rabby|revoke|mint|presale|whitelist)/i.test(d)) return 'crypto-drainer';
  if (/(?:roblox|robux|rbx|roblx)/i.test(d)) return 'roblox-gaming';
  if (/(?:casino|gambling|bet|win|spin|jackpot|sedowin|wormwin|lenuwin)/i.test(d)) return 'casino-fraud';
  return fallback;
}

export async function buildDataset(): Promise<void> {
  const start = Date.now();
  console.log('Fetching official domain whitelist...');
  const officialRes = await fetch('https://raw.githubusercontent.com/Dogino/Discord-Phishing-URLs/main/official-domains.txt').catch(() => null);
  const officialSet = new Set<string>([
    'github.com', 'google.com', 'youtube.com', 'twitter.com', 'x.com',
    'discord.com', 'discord.gg', 'discord.gift', 'discord.media', 'discord.co',
    'discordapp.com', 'steamcommunity.com', 'steampowered.com', 'roblox.com',
    'pollinations.ai', 'enter.pollinations.ai', 'pollinations.github.io',
    'raw.githubusercontent.com', 'gist.github.com',
    'ethereum.org', 'solana.com', 'bitcoin.org',
    'uniswap.org', 'opensea.io', 'metamask.io', 'phantom.app',
    'binance.com', 'coinbase.com', 'kraken.com',
    'etherscan.io', 'solscan.io', 'bscscan.com',
    'cloudflare.com', 'jsdelivr.net', 'github.io', 'gitlab.com',
    'reddit.com', 'twitch.tv', 'spotify.com', 'medium.com'
  ]);

  if (officialRes && officialRes.ok) {
    const text = await officialRes.text();
    for (const line of text.split('\n')) {
      const clean = line.trim().toLowerCase();
      if (clean && !clean.startsWith('//') && !clean.startsWith('#')) {
        officialSet.add(clean);
      }
    }
  }

  const domainMap = new Map<string, string>();

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

        let isOfficial = officialSet.has(d);
        if (!isOfficial) {
          const parts = d.split('.');
          for (let i = 1; i < parts.length - 1; i++) {
            if (officialSet.has(parts.slice(i).join('.'))) {
              isOfficial = true;
              break;
            }
          }
        }
        if (isOfficial) continue;

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
  const allJsonPath = resolve(DATA_DIR, 'all.json');
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
