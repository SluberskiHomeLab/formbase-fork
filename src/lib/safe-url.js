// Guards against server-side request forgery through user-supplied URLs
// (webhook_url) and against javascript:/data: payloads stored in redirect_url.
//
// Two layers:
//   validateHttpUrl()  - cheap, synchronous, runs when the URL is saved.
//   resolveSafeUrl()   - resolves DNS and rejects private destinations, runs
//                        immediately before the request is made.
//
// The second layer is what matters: a hostname that looks public can resolve
// to 169.254.169.254, and only a post-resolution check catches that.

const dns = require('dns').promises;
const net = require('net');

const ALLOW_PRIVATE = process.env.SSRF_ALLOW_PRIVATE === '1';

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

// CIDR blocks that must never be reachable from a user-supplied URL.
const BLOCKED_V4 = [
  ['0.0.0.0', 8],         // "this" network
  ['10.0.0.0', 8],        // RFC1918
  ['100.64.0.0', 10],     // CGNAT
  ['127.0.0.0', 8],       // loopback
  ['169.254.0.0', 16],    // link-local -- cloud instance metadata lives here
  ['172.16.0.0', 12],     // RFC1918
  ['192.0.0.0', 24],      // IETF protocol assignments
  ['192.0.2.0', 24],      // TEST-NET-1
  ['192.168.0.0', 16],    // RFC1918
  ['198.18.0.0', 15],     // benchmarking
  ['198.51.100.0', 24],   // TEST-NET-2
  ['203.0.113.0', 24],    // TEST-NET-3
  ['224.0.0.0', 4],       // multicast
  ['240.0.0.0', 4]        // reserved / broadcast
];

function isBlockedV4(ip) {
  const value = ipv4ToInt(ip);
  return BLOCKED_V4.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (value & mask) === (ipv4ToInt(base) & mask);
  });
}

function isBlockedV6(ip) {
  const addr = ip.toLowerCase().split('%')[0];
  if (addr === '::1' || addr === '::') return true;
  // IPv4-mapped (::ffff:127.0.0.1) -- judge on the embedded address
  const mapped = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedV4(mapped[1]);
  const head = parseInt(addr.split(':')[0] || '0', 16);
  if ((head & 0xfe00) === 0xfc00) return true;   // fc00::/7 unique-local
  if ((head & 0xffc0) === 0xfe80) return true;   // fe80::/10 link-local
  if (addr.startsWith('2001:db8')) return true;  // documentation
  return false;
}

function isBlockedAddress(ip) {
  const family = net.isIP(ip);
  if (family === 4) return isBlockedV4(ip);
  if (family === 6) return isBlockedV6(ip);
  return true; // unparseable -> refuse
}

/**
 * Synchronous validation for values being persisted. Returns a normalised URL
 * string, or throws an Error whose message is safe to show the user.
 */
function validateHttpUrl(value, label = 'URL') {
  let parsed;
  try {
    parsed = new URL(String(value));
  } catch {
    throw new Error(`${label} is not a valid URL`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`${label} must use http or https`);
  }
  if (!parsed.hostname) throw new Error(`${label} is missing a hostname`);

  // Literal private address written straight into the field. Hostnames that
  // resolve privately are caught later by resolveSafeUrl().
  if (!ALLOW_PRIVATE && net.isIP(parsed.hostname) && isBlockedAddress(parsed.hostname)) {
    throw new Error(`${label} may not point at a private or loopback address`);
  }
  const bare = parsed.hostname.replace(/^\[|\]$/g, '');
  if (!ALLOW_PRIVATE && net.isIP(bare) && isBlockedAddress(bare)) {
    throw new Error(`${label} may not point at a private or loopback address`);
  }
  if (!ALLOW_PRIVATE && /^(localhost|.*\.localhost|.*\.local|.*\.internal)$/i.test(parsed.hostname)) {
    throw new Error(`${label} may not point at a private or loopback address`);
  }
  return parsed.toString();
}

/**
 * Resolves the hostname and rejects if ANY returned address is private.
 * Call immediately before making the request.
 */
async function resolveSafeUrl(value, label = 'URL') {
  const url = new URL(validateHttpUrl(value, label));
  if (ALLOW_PRIVATE) return url;

  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (isBlockedAddress(host)) throw new Error(`${label} resolves to a blocked address`);
    return url;
  }

  let addresses;
  try {
    addresses = await dns.lookup(host, { all: true });
  } catch {
    throw new Error(`${label} could not be resolved`);
  }
  if (!addresses.length) throw new Error(`${label} could not be resolved`);
  for (const { address } of addresses) {
    if (isBlockedAddress(address)) {
      throw new Error(`${label} resolves to a blocked address (${address})`);
    }
  }
  return url;
}

module.exports = { validateHttpUrl, resolveSafeUrl, isBlockedAddress };
