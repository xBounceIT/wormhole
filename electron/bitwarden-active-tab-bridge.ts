export type BitwardenActiveTabContext = {
  physicalUrl: string;
  logicalUrl: string;
  pageMarker?: string;
};

export function selectBitwardenTabRegistrationPartition(
  preparedPartition: string | undefined,
  activePartition: string | undefined,
): string | undefined {
  return preparedPartition && preparedPartition === activePartition ? preparedPartition : undefined;
}

const pageMarkerAttribute = 'data-wormhole-bitwarden-active-tab';

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

export function buildBitwardenPageMarkerScript(marker: string): string {
  return `document.documentElement?.setAttribute(${JSON.stringify(pageMarkerAttribute)}, ${JSON.stringify(marker)});`;
}

export function buildBitwardenActiveTabBridgeScript(context: BitwardenActiveTabContext): string {
  return `
    (() => {
      const context = ${JSON.stringify(context)};
      if (location.protocol !== 'chrome-extension:' || !globalThis.chrome?.tabs?.query) return;

      const tabsApi = chrome.tabs;
      const nativeQuery = tabsApi.query.bind(tabsApi);
      const normalizeUrl = (value) => {
        try { return new URL(value).href; }
        catch { return value; }
      };
      const physicalUrl = normalizeUrl(context.physicalUrl);
      const findSourceTab = async (allTabs) => {
        const candidates = Array.isArray(allTabs)
          ? allTabs.filter((tab) => tab?.url && normalizeUrl(tab.url) === physicalUrl)
          : [];
        if (candidates.length <= 1) return candidates[0] ?? null;

        if (context.pageMarker && globalThis.chrome?.scripting?.executeScript) {
          for (const tab of candidates) {
            if (!Number.isInteger(tab.id)) continue;
            try {
              const results = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: (attribute, marker) => {
                  const root = document.documentElement;
                  if (root?.getAttribute(attribute) !== marker) return false;
                  root.removeAttribute(attribute);
                  return true;
                },
                args: [${JSON.stringify(pageMarkerAttribute)}, context.pageMarker],
              });
              if (results.some((result) => result?.result === true)) return tab;
            } catch {
              // Fall back to the browser's recency signal below.
            }
          }
        }
        return candidates.reduce(
          (latest, tab) =>
            !latest || (tab.lastAccessed ?? 0) > (latest.lastAccessed ?? 0) ? tab : latest,
          null,
        );
      };
      const projectActiveTab = async (allTabs) => {
        const sourceTab = await findSourceTab(allTabs);
        return sourceTab ? [{ ...sourceTab, active: true, url: context.logicalUrl }] : null;
      };
      const shouldProject = (queryInfo) =>
        queryInfo?.active === true && queryInfo?.currentWindow === true;
      const bridgedQuery = (queryInfo, callback) => {
        if (!shouldProject(queryInfo)) {
          return typeof callback === 'function'
            ? nativeQuery(queryInfo, callback)
            : nativeQuery(queryInfo);
        }
        if (typeof callback === 'function') {
          return nativeQuery({}, async (allTabs) => {
            const projected = await projectActiveTab(allTabs);
            if (projected) callback(projected);
            else nativeQuery(queryInfo, callback);
          });
        }
        return nativeQuery({}).then(async (allTabs) =>
          (await projectActiveTab(allTabs)) ?? nativeQuery(queryInfo),
        );
      };
      try {
        Object.defineProperty(tabsApi, 'query', {
          configurable: true,
          writable: true,
          value: bridgedQuery,
        });
      } catch {
        tabsApi.query = bridgedQuery;
      }
    })()
  `;
}

function parseWebUrl(value: string): URL | undefined {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed : undefined;
  } catch {
    return undefined;
  }
}
