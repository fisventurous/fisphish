# fisphish

Aggregated, de-duplicated threat intelligence feeds targeting Discord token grabbers, fake Nitro campaigns, Steam trading fraud, and Web3 crypto drainers.

Automatically refreshed twice daily via GitHub Actions. Legitimate platforms (Discord, GitHub, Steam, Pollinations, core Web3 infrastructure) are whitelisted to prevent false positives.

## Raw Endpoints

| Feed | Format | Description | Raw URL |
|---|---|---|---|
| **All (Categorised)** | JSON | Grouped by threat category | [`all.json`](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/all.json) |
| **All Domains** | TXT | Flat newline list of all ~476k domains | [`domains.txt`](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/domains.txt) |
| **Crypto Drainers** | TXT | Fake airdrops, wallet drainers & phishing DEXs | [`crypto-drainers.txt`](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/crypto-drainers.txt) |
| **Discord Scams** | TXT | Token grabbers, fake Nitro & server verification lures | [`discord-scams.txt`](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/discord-scams.txt) |
| **Steam Fraud** | TXT | Trade offer scams & fake Steam Community portals | [`steam-fraud.txt`](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/steam-fraud.txt) |
| **Casino Fraud** | TXT | Fake crypto casinos & rigged gambling promo sites | [`casino-fraud.txt`](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/casino-fraud.txt) |

## Breakdown

| Threat Category | Active Domains |
|---|---|
| Crypto Drainers & Phishing | ~426,000 |
| Discord Nitro & Token Grabbers | ~33,500 |
| Steam Trade Fraud | ~10,000 |
| Casino & Gambling Fraud | ~3,700 |
| General Phishing / Malware | ~1,800 |
| Roblox & Gaming Scams | ~1,000 |
| **Total Unique Domains** | **~476,000** |

## Integration

### Python
```python
import urllib.request, json

req = urllib.request.urlopen("https://raw.githubusercontent.com/fisventurous/fisphish/main/data/all.json")
data = json.loads(req.read().decode())

def is_phishing(domain: str) -> bool:
    clean = domain.lower().strip()
    return any(clean in domains for domains in data.values())
```

### Node / TypeScript
```typescript
const res = await fetch('https://raw.githubusercontent.com/fisventurous/fisphish/main/data/domains.txt');
const text = await res.text();
const blocked = new Set(text.split('\n').filter(Boolean));

function isPhishing(domain: string): boolean {
  return blocked.has(domain.toLowerCase().trim());
}
```

### Pi-hole / AdGuard / DNS Sinkhole
Add the raw `domains.txt` link directly to your adlists:
```text
https://raw.githubusercontent.com/fisventurous/fisphish/main/data/domains.txt
```

## Local Build

If you want to run the pipeline manually or compile custom feeds:

```bash
git clone https://github.com/fisventurous/fisphish.git
cd fisphish
npm install
npm run build
```

The compiled datasets will be generated under `data/`.

## Upstream Sources & Attribution

This dataset aggregates and sanitises active threat indicators maintained by independent security researchers and open-source communities:

| Project | Maintainer / Source | Focus |
|---|---|---|
| [ScamSniffer](https://github.com/scamsniffer/scam-database) | ScamSniffer Team | Real-time Web3 wallet drainers & DaaS infrastructure |
| [MetaMask eth-phishing-detect](https://github.com/MetaMask/eth-phishing-detect) | ConsenSys / MetaMask | Crypto interaction blacklist & token theft hosts |
| [Sinking Yachts](https://phish.sinking.yachts) | Sinking Yachts Community | Discord phishing API & active Nitro lures |
| [Discord Malicious Domains](https://github.com/daltonmenezes/discord-malicious-domains) | Dalton Menezes | Discord token grabbers & spoofed platforms |
| [Discord-AntiScam](https://github.com/Discord-AntiScam/scam-links) | Discord-AntiScam Team | Community-reported Discord scam links |
| [Discord Phishing URLs](https://github.com/Dogino/Discord-Phishing-URLs) | Dogino | Pi-hole adlists & scam URLs targeting gamers |
| [Discord Phishing Links](https://github.com/nikolaischunk/discord-phishing-links) | Nikolai Schunk | Suspicious and confirmed Discord phishing hosts |
| [Anti-Scam Database](https://github.com/Andre601/anti-scam-database) | Andre601 | Documented campaign links & affected platforms |
| [URLhaus](https://urlhaus.abuse.ch) | abuse.ch | Actively tracked malware and payload delivery URLs |

Special thanks to all upstream researchers keeping community platforms secure.

## Licence

MIT (c) 2026 fisventurous. Upstream feeds remain property of their respective maintainers.
