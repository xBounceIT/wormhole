export type BitwardenActiveTabContext = {
  physicalUrl: string;
  logicalUrl: string;
};

export function selectBitwardenTabRegistrationPartition(
  preparedPartition: string | undefined,
  activePartition: string | undefined,
): string | undefined {
  return preparedPartition && preparedPartition === activePartition ? preparedPartition : undefined;
}

export function createBitwardenActiveTabContext(
  navigateUrl: string,
  originalUrl: string | undefined,
  currentUrl: string,
): BitwardenActiveTabContext | undefined {
  const navigate = parseWebUrl(navigateUrl);
  const physical = parseWebUrl(currentUrl) ?? navigate;
  if (!navigate || !physical) return undefined;

  const original = originalUrl ? parseWebUrl(originalUrl) : undefined;
  if (!original || physical.origin.toLowerCase() !== navigate.origin.toLowerCase()) {
    return { physicalUrl: physical.href, logicalUrl: physical.href };
  }

  const logical = new URL(physical.href);
  logical.protocol = original.protocol;
  logical.hostname = original.hostname;
  logical.port = original.port;
  return { physicalUrl: physical.href, logicalUrl: logical.href };
}

function parseWebUrl(value: string): URL | undefined {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed : undefined;
  } catch {
    return undefined;
  }
}
