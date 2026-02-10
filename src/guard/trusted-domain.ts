/**
 * Trusted Domain - Check if URLs are from trusted sources
 */

import { isTrustedUrl, extractUrls, isRiskyUrlPattern } from '../config/domains.js';

export interface TrustedDomainResult {
  allTrusted: boolean;
  /** Whether any URL matches a risky pattern (user-controlled content from trusted domains) */
  hasRiskyUrls: boolean;
  urls: string[];
  trustedUrls: string[];
  untrustedUrls: string[];
  riskyUrls: string[];
}

/**
 * Check all URLs in a command and determine if they're from trusted domains
 */
export function checkTrustedDomains(command: string): TrustedDomainResult {
  const urls = extractUrls(command);

  if (urls.length === 0) {
    return {
      allTrusted: true, // No URLs means nothing untrusted
      hasRiskyUrls: false,
      urls: [],
      trustedUrls: [],
      untrustedUrls: [],
      riskyUrls: [],
    };
  }

  const trustedUrls: string[] = [];
  const untrustedUrls: string[] = [];
  const riskyUrls: string[] = [];

  for (const url of urls) {
    if (isTrustedUrl(url)) {
      trustedUrls.push(url);
    } else {
      untrustedUrls.push(url);
    }
    // Check for risky patterns even on trusted domains
    if (isRiskyUrlPattern(url)) {
      riskyUrls.push(url);
    }
  }

  return {
    allTrusted: untrustedUrls.length === 0,
    hasRiskyUrls: riskyUrls.length > 0,
    urls,
    trustedUrls,
    untrustedUrls,
    riskyUrls,
  };
}

