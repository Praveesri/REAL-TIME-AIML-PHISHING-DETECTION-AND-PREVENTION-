/**
 * featureExtraction.js
 * Ports backend/feature_extraction.py to pure JavaScript.
 * Extracts URL-based features only (no HTTP requests to external sites).
 * 100% client-side — works on GitHub Pages with no backend.
 */

/**
 * Extract phishing-detection features from a URL string.
 * Returns an object matching the feature columns used by the ML model:
 *   url_length, is_long_url, has_at_symbol, has_ip_address,
 *   num_hyphens, has_hyphen_in_domain, num_subdomains,
 *   is_https, has_suspicious_words,
 *   has_form_with_action, has_password_field, has_hidden_elements
 */
export function extractFeatures(rawUrl) {
  let url = rawUrl.trim();

  // Add scheme if missing
  if (!/^https?:\/\//i.test(url)) {
    url = 'http://' + url;
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null; // Invalid URL
  }

  const hostname = parsed.hostname.toLowerCase(); // e.g. "sub.example.com"

  // --- 1. URL Length ---
  const urlLength = url.length;
  const isLongUrl = urlLength > 54 ? 1 : 0;

  // --- 2. @ Symbol ---
  const hasAtSymbol = url.includes('@') ? 1 : 0;

  // --- 3. IP Address in hostname ---
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const hasIpAddress = ipPattern.test(hostname) ? 1 : 0;

  // --- 4. Hyphens in domain ---
  // Extract registrable domain (last two parts): e.g. "example.com"
  const parts = hostname.split('.');
  const registrableDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  const numHyphens = (registrableDomain.match(/-/g) || []).length;
  const hasHyphenInDomain = numHyphens > 0 ? 1 : 0;

  // --- 5. Subdomains ---
  // Subdomains = everything before the registrable domain
  const subdomainPart = parts.slice(0, -2).join('.');
  let numSubdomains = 0;
  if (subdomainPart && subdomainPart !== 'www') {
    numSubdomains = subdomainPart.split('.').filter(Boolean).length;
  }

  // --- 6. HTTPS ---
  const isHttps = parsed.protocol === 'https:' ? 1 : 0;

  // --- 7. Suspicious Words ---
  const suspiciousWords = [
    'secure', 'account', 'webscr', 'login', 'ebayisapi',
    'signin', 'banking', 'confirm', 'update', 'verify',
    'paypal', 'password', 'credential', 'wallet', 'support',
  ];
  const urlLower = url.toLowerCase();
  const hasSuspiciousWords = suspiciousWords.some(w => urlLower.includes(w)) ? 1 : 0;

  // --- 8. Page content features ---
  // We cannot fetch page content client-side (CORS).
  // Heuristic: infer from URL patterns only.
  const hasFormWithAction = hasSuspiciousWords || hasIpAddress ? 1 : 0;
  const hasPasswordField = (hasSuspiciousWords && !isHttps) || hasIpAddress ? 1 : 0;
  const hasHiddenElements = hasIpAddress || (numHyphens > 2) ? 1 : 0;

  return {
    url_length: urlLength,
    is_long_url: isLongUrl,
    has_at_symbol: hasAtSymbol,
    has_ip_address: hasIpAddress,
    num_hyphens: numHyphens,
    has_hyphen_in_domain: hasHyphenInDomain,
    num_subdomains: numSubdomains,
    is_https: isHttps,
    has_suspicious_words: hasSuspiciousWords,
    has_form_with_action: hasFormWithAction,
    has_password_field: hasPasswordField,
    has_hidden_elements: hasHiddenElements,
  };
}
