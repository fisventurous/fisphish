const { domainToASCII, isIP } = require('node:url');

const CATEGORIES = new Set([
  'Crypto Drainer / Fake Airdrop',
  'Discord Nitro / Token Grabber',
  'Steam Trade / Skin Fraud',
  'Casino / Gambling Fraud',
  'General Phishing / Malware'
]);

const PROTECTED_HOSTS = new Set([
  'github.com', 'google.com', 'youtube.com', 'twitter.com', 'x.com',
  'discord.com', 'discord.gg', 'steamcommunity.com', 'pollinations.ai',
  'cloudflare.com', 'microsoft.com', 'apple.com', 'amazon.com', 'vercel.app'
]);

function parseDomainSubmission(body) {
  const text = String(body ?? '');
  const domainMatch = text.match(/(?:^|\r?\n)### Malicious Domain or URL\r?\n([^\r\n]*)/i);
  const categoryMatch = text.match(/(?:^|\r?\n)### Threat Category\r?\n([^\r\n]*)/i);
  const raw = domainMatch?.[1]?.trim();
  const category = categoryMatch?.[1]?.trim();

  if (!raw || !CATEGORIES.has(category)) return null;
  if (/^[a-z][a-z\d+.-]*:/i.test(raw) && !/^https?:\/\//i.test(raw)) return null;

  let host;
  try {
    const url = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
    if (url.username || url.password) return null;
    host = domainToASCII(url.hostname.replace(/\.$/, '')).toLowerCase();
  } catch {
    return null;
  }

  if (!host || host.length > 253 || isIP(host)) return null;
  const labels = host.split('.');
  if (labels.length < 2 || labels.some(label => (
    label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  ))) return null;

  return host;
}

function isProtectedDomain(domain) {
  return [...PROTECTED_HOSTS].some(host => (
    domain === host || (host !== 'vercel.app' && domain.endsWith(`.${host}`))
  ));
}

module.exports = { isProtectedDomain, parseDomainSubmission };
