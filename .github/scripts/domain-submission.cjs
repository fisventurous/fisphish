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

function parseDomain(raw) {
  if (!raw || /^[a-z][a-z\d+.-]*:/i.test(raw) && !/^https?:\/\//i.test(raw)) return null;
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

function parseDomainSubmission(body) {
  const text = String(body ?? '');
  const domainMatch = text.match(/(?:^|\r?\n)### Malicious Domain or URL\r?\n([\s\S]*?)(?=\r?\n### |$)/i);
  const categoryMatch = text.match(/(?:^|\r?\n)### Threat Category\r?\n([^\r\n]*)/i);
  const rawDomains = domainMatch?.[1].split(/\r?\n/).map(value => value.trim()).filter(Boolean);
  const category = categoryMatch?.[1]?.trim();

  if (!rawDomains?.length || rawDomains.length > 20 || !CATEGORIES.has(category)) return null;

  const domains = rawDomains.map(parseDomain);
  if (domains.some(domain => !domain) || new Set(domains).size !== domains.length) return null;

  return { domains, category };
}

function isProtectedDomain(domain) {
  return [...PROTECTED_HOSTS].some(host => (
    domain === host || (host !== 'vercel.app' && domain.endsWith(`.${host}`))
  ));
}

module.exports = { isProtectedDomain, parseDomainSubmission };
