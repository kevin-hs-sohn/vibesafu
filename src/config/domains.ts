/**
 * Trusted domains whitelist for security checks
 */

// Domains that are considered safe for script downloads and package installations
export const TRUSTED_DOMAINS: string[] = [
  // Package managers & registries
  'npmjs.com',
  'registry.npmjs.org',
  'yarnpkg.com',
  'pypi.org',
  'pypa.io',
  'crates.io',
  'rubygems.org',
  'packagist.org',

  // GitHub
  'github.com',
  'raw.githubusercontent.com',
  'gist.github.com',
  'objects.githubusercontent.com',

  // Other Git hosts
  'gitlab.com',
  'bitbucket.org',

  // Runtime installers
  'bun.sh',
  'deno.land',
  'nodejs.org',
  'rustup.rs',

  // Docker
  'get.docker.com',
  'download.docker.com',

  // Homebrew
  'brew.sh',
  'formulae.brew.sh',

  // Cloud providers (official)
  'amazonaws.com',
  'storage.googleapis.com',
  'azure.microsoft.com',

  // CDNs for packages
  'unpkg.com',
  'cdn.jsdelivr.net',
  'cdnjs.cloudflare.com',

  // Vercel
  'vercel.com',
  'vercel.sh',
];

/**
 * Check if a hostname matches a trusted domain
 * Supports exact match and subdomain matching
 */
export function isDomainTrusted(hostname: string): boolean {
  const normalizedHost = hostname.toLowerCase();

  return TRUSTED_DOMAINS.some((domain) => {
    const normalizedDomain = domain.toLowerCase();
    return (
      normalizedHost === normalizedDomain ||
      normalizedHost.endsWith('.' + normalizedDomain)
    );
  });
}

/**
 * Extract hostname from URL safely
 */
export function extractHostname(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return null;
  }
}

/**
 * Check if a URL is from a trusted domain
 */
export function isTrustedUrl(url: string): boolean {
  const hostname = extractHostname(url);
  if (!hostname) {
    return false;
  }
  return isDomainTrusted(hostname);
}

/**
 * Extract all URLs from a command string
 */
export function extractUrls(command: string): string[] {
  const urlPattern = /https?:\/\/[^\s"'<>]+/gi;
  const matches = command.match(urlPattern);
  return matches ?? [];
}
