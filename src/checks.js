// The actual checks. Each one looks at the response and returns a finding:
// { name, status: 'pass' | 'warn' | 'fail' | 'info', detail }
// Scoring happens in score.js, this file only describes what was found.

// How much each missing/broken thing costs, roughly by real-world impact.
export const WEIGHTS = { fail: 15, warn: 6 };

export function checkHttps(inputUrl, finalUrl) {
  const startedHttps = inputUrl.protocol === 'https:';
  const endedHttps = finalUrl.startsWith('https://');

  if (endedHttps && !startedHttps) {
    return {
      name: 'HTTPS redirect',
      status: 'pass',
      detail: 'http:// upgrades to https:// automatically',
    };
  }
  if (endedHttps) {
    return { name: 'HTTPS', status: 'pass', detail: 'site is served over HTTPS' };
  }
  return {
    name: 'HTTPS',
    status: 'fail',
    detail: 'site is served over plain HTTP, traffic can be read or modified in transit',
  };
}

export function checkHsts(headers, isHttps) {
  const value = headers.get('strict-transport-security');
  if (!value) {
    return {
      name: 'Strict-Transport-Security',
      status: isHttps ? 'fail' : 'warn',
      detail: isHttps
        ? 'missing. Browsers are never told to insist on HTTPS, so a first visit can be downgraded'
        : 'missing (matters once the site runs on HTTPS)',
    };
  }
  // A max-age under a day is basically decorative.
  const match = value.match(/max-age=(\d+)/i);
  if (match && Number(match[1]) < 86400) {
    return {
      name: 'Strict-Transport-Security',
      status: 'warn',
      detail: `present but max-age is only ${match[1]}s, use at least 6 months (15552000)`,
    };
  }
  return { name: 'Strict-Transport-Security', status: 'pass', detail: value };
}

export function checkCsp(headers) {
  const value = headers.get('content-security-policy');
  if (!value) {
    return {
      name: 'Content-Security-Policy',
      status: 'fail',
      detail: 'missing. Nothing restricts where scripts and assets can load from, so injected content runs freely',
    };
  }
  const warnings = [];
  if (/unsafe-inline/.test(value)) warnings.push("allows 'unsafe-inline'");
  if (/unsafe-eval/.test(value)) warnings.push("allows 'unsafe-eval'");
  if (warnings.length) {
    return {
      name: 'Content-Security-Policy',
      status: 'warn',
      detail: `present but ${warnings.join(' and ')}, which weakens it a lot`,
    };
  }
  return { name: 'Content-Security-Policy', status: 'pass', detail: 'present, no unsafe-inline/unsafe-eval' };
}

export function checkFrameProtection(headers) {
  const xfo = headers.get('x-frame-options');
  const csp = headers.get('content-security-policy') || '';
  if (xfo) {
    return { name: 'Clickjacking protection', status: 'pass', detail: `X-Frame-Options: ${xfo}` };
  }
  if (/frame-ancestors/.test(csp)) {
    return { name: 'Clickjacking protection', status: 'pass', detail: 'covered by CSP frame-ancestors' };
  }
  return {
    name: 'Clickjacking protection',
    status: 'warn',
    detail: 'no X-Frame-Options and no CSP frame-ancestors, other sites can embed this one in an iframe (clickjacking)',
  };
}

export function checkContentTypeSniffing(headers) {
  const value = headers.get('x-content-type-options');
  if (value && value.toLowerCase().includes('nosniff')) {
    return { name: 'X-Content-Type-Options', status: 'pass', detail: 'nosniff' };
  }
  return {
    name: 'X-Content-Type-Options',
    status: 'warn',
    detail: 'missing nosniff, browsers may guess file types and execute things they should not',
  };
}

export function checkReferrerPolicy(headers) {
  const value = headers.get('referrer-policy');
  if (value) {
    return { name: 'Referrer-Policy', status: 'pass', detail: value };
  }
  return {
    name: 'Referrer-Policy',
    status: 'warn',
    detail: 'missing, full page URLs (sometimes with tokens in them) leak to third-party sites',
  };
}

export function checkPermissionsPolicy(headers) {
  const value = headers.get('permissions-policy') || headers.get('feature-policy');
  if (value) {
    return { name: 'Permissions-Policy', status: 'pass', detail: 'present' };
  }
  return {
    name: 'Permissions-Policy',
    status: 'warn',
    detail: 'missing, embedded content can ask for camera/mic/location without the site opting in',
  };
}

export function checkVersionDisclosure(headers) {
  const leaked = [];
  const server = headers.get('server');
  const poweredBy = headers.get('x-powered-by');
  // "Vercel" or "cloudflare" alone is fine, "Apache/2.4.41 (Ubuntu)" is a shopping list.
  if (server && /\d+\.\d+/.test(server)) leaked.push(`Server: ${server}`);
  if (poweredBy) leaked.push(`X-Powered-By: ${poweredBy}`);
  if (leaked.length) {
    return {
      name: 'Version disclosure',
      status: 'warn',
      detail: `response advertises its stack: ${leaked.join(', ')}`,
    };
  }
  return { name: 'Version disclosure', status: 'pass', detail: 'no framework/version banner in the headers' };
}

export function checkCookies(headers) {
  const cookies = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [];
  if (!cookies.length) {
    return [{ name: 'Cookies', status: 'info', detail: 'this response sets no cookies, nothing to check' }];
  }
  return cookies.map((raw) => {
    const name = raw.split('=')[0].trim();
    const flags = raw.toLowerCase();
    const missing = [];
    if (!flags.includes('secure')) missing.push('Secure');
    if (!flags.includes('httponly')) missing.push('HttpOnly');
    if (!flags.includes('samesite')) missing.push('SameSite');
    if (missing.length) {
      return {
        name: `Cookie "${name}"`,
        status: missing.includes('HttpOnly') ? 'fail' : 'warn',
        detail: `missing flags: ${missing.join(', ')}`,
      };
    }
    return { name: `Cookie "${name}"`, status: 'pass', detail: 'Secure, HttpOnly and SameSite all set' };
  });
}

export function checkCors(headers) {
  const acao = headers.get('access-control-allow-origin');
  const acac = headers.get('access-control-allow-credentials');
  if (acao === '*' && acac === 'true') {
    return {
      name: 'CORS',
      status: 'fail',
      detail: 'Access-Control-Allow-Origin: * together with credentials allowed, any site can read authenticated responses',
    };
  }
  if (acao === '*') {
    return {
      name: 'CORS',
      status: 'info',
      detail: 'Access-Control-Allow-Origin: * (fine for public data, risky for anything user-specific)',
    };
  }
  return { name: 'CORS', status: 'pass', detail: 'no wildcard cross-origin access' };
}

export function runAllChecks(inputUrl, response) {
  const headers = response.headers;
  const finalUrl = response.url || inputUrl.toString();
  const isHttps = finalUrl.startsWith('https://');

  const findings = [
    checkHttps(inputUrl, finalUrl),
    checkHsts(headers, isHttps),
    checkCsp(headers),
    checkFrameProtection(headers),
    checkContentTypeSniffing(headers),
    checkReferrerPolicy(headers),
    checkPermissionsPolicy(headers),
    checkVersionDisclosure(headers),
    ...checkCookies(headers),
    checkCors(headers),
  ];

  return { finalUrl, findings };
}
