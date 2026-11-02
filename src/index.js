#!/usr/bin/env node
import { runAllChecks } from './checks.js';
import { scoreFindings, gradeFor } from './score.js';
import { printReport } from './report.js';

const DEFAULT_TIMEOUT_MS = 10000;

function usage() {
  console.log(`Usage: headerpatrol <url> [--json] [--timeout <ms>]

Checks a website's security headers, cookie flags and HTTPS setup,
then gives it a score out of 100.

Example:
  headerpatrol example.com
  headerpatrol https://example.com --json`);
}

function parseArgs(argv) {
  const args = { url: null, json: false, timeout: DEFAULT_TIMEOUT_MS };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--timeout') args.timeout = Number(argv[++i]) || DEFAULT_TIMEOUT_MS;
    else if (a === '-h' || a === '--help') args.help = true;
    else if (!a.startsWith('-')) args.url = a;
  }
  return args;
}

// People type "example.com", not "https://example.com". Meet them halfway.
function normalizeUrl(raw) {
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  return new URL(withScheme);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.url) {
    usage();
    process.exit(args.help ? 0 : 1);
  }

  let url;
  try {
    url = normalizeUrl(args.url);
  } catch {
    console.error(`Not a valid URL: ${args.url}`);
    process.exit(1);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), args.timeout);

  let response;
  try {
    response = await fetch(url, {
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        // A normal browser-ish UA; some CDNs serve different headers to bots.
        'user-agent':
          'Mozilla/5.0 (compatible; headerpatrol/1.0; +https://github.com/harshit-exe-dev/headerpatrol)',
        // A fixed foreign Origin so wildcard CORS shows up in the response.
        origin: 'https://headerpatrol.check',
      },
    });
    // We only need the headers; don't download a huge body for nothing.
    if (response.body) response.body.cancel().catch(() => {});
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      console.error(`Timed out after ${args.timeout}ms: ${url}`);
    } else {
      console.error(`Could not fetch ${url}: ${err.cause?.message || err.message}`);
    }
    process.exit(1);
  }
  clearTimeout(timer);

  const { finalUrl, findings } = runAllChecks(url, response);
  const score = scoreFindings(findings);
  const grade = gradeFor(score);

  if (args.json) {
    console.log(
      JSON.stringify({ target: url.toString(), finalUrl, status: response.status, score, grade, findings }, null, 2)
    );
  } else {
    console.log(printReport(url.toString(), finalUrl, findings, score, grade));
  }

  // Exit non-zero on a failing grade so it can gate a CI pipeline.
  process.exit(grade === 'F' || grade === 'D' ? 2 : 0);
}

main();
