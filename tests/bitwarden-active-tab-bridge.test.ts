import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import {
  buildBitwardenActiveTabBridgeScript,
  buildBitwardenPageMarkerScript,
  createBitwardenActiveTabContext,
  selectBitwardenTabRegistrationPartition,
  type BitwardenActiveTabContext,
} from '../electron/bitwarden-active-tab-bridge.ts';

type TestTab = { id: number; active: boolean; url: string; lastAccessed: number };
type QueryCallback = (value: TestTab[]) => void;

function installBridge(context: BitwardenActiveTabContext) {
  const allTabs: TestTab[] = [
    { id: 1, active: false, url: context.physicalUrl, lastAccessed: 10 },
    { id: 2, active: false, url: context.physicalUrl, lastAccessed: 20 },
    { id: 3, active: true, url: 'chrome-extension://bitwarden/popup.html', lastAccessed: 30 },
  ];
  const tabs = {
    query(query: Record<string, unknown>, callback?: QueryCallback) {
      const value = Object.keys(query).length === 0 ? allTabs : allTabs.filter((tab) => tab.active);
      if (callback) return callback(value);
      return Promise.resolve(value);
    },
  };
  const scripting = {
    executeScript(request: { target: { tabId: number } }) {
      return Promise.resolve([{ result: request.target.tabId === 1 }]);
    },
  };
  vm.runInNewContext(buildBitwardenActiveTabBridgeScript(context), {
    chrome: { tabs, scripting },
    location: { protocol: 'chrome-extension:' },
    URL,
  });
  return tabs;
}

test('direct and SOCKS targets expose the live redirect URL', () => {
  const context = createBitwardenActiveTabContext(
    'https://appliance.example/',
    undefined,
    'https://login.appliance.example/sso/callback#complete',
  );
  assert.deepEqual(context, {
    physicalUrl: 'https://login.appliance.example/sso/callback#complete',
    logicalUrl: 'https://login.appliance.example/sso/callback#complete',
  });
});

test('forwarder targets expose the original authority with the live path', () => {
  const context = createBitwardenActiveTabContext(
    'https://127.0.0.1:51515/',
    'https://appliance.example:8443/',
    'https://127.0.0.1:51515/admin/page?section=vpn#status',
  );
  assert.deepEqual(context, {
    physicalUrl: 'https://127.0.0.1:51515/admin/page?section=vpn#status',
    logicalUrl: 'https://appliance.example:8443/admin/page?section=vpn#status',
  });
});

test('non-web current URLs fall back to the initial target', () => {
  assert.deepEqual(
    createBitwardenActiveTabContext('https://appliance.example/', undefined, 'about:blank'),
    {
      physicalUrl: 'https://appliance.example/',
      logicalUrl: 'https://appliance.example/',
    },
  );
});

test('HTTPS tabs register only after Bitwarden exposes an active popup context', () => {
  assert.equal(selectBitwardenTabRegistrationPartition('persist:prepared', undefined), undefined);
  assert.equal(
    selectBitwardenTabRegistrationPartition('persist:prepared', 'persist:other'),
    undefined,
  );
  assert.equal(
    selectBitwardenTabRegistrationPartition('persist:prepared', 'persist:prepared'),
    'persist:prepared',
  );
});

test('Bitwarden callback queries select the marked source tab', async () => {
  const context = {
    physicalUrl: 'https://127.0.0.1:51515/',
    logicalUrl: "https://appliance.example/a'b?value=1",
    pageMarker: 'marker',
  };
  const tabs = installBridge(context);
  const projected = await new Promise<TestTab[]>((resolve) => {
    tabs.query({ active: true, currentWindow: true }, resolve);
  });
  assert.equal(projected.length, 1);
  assert.equal(projected[0].id, 1);
  assert.equal(projected[0].url, context.logicalUrl);
  assert.equal(projected[0].active, true);
});

test('Bitwarden promise queries select the marked source tab', async () => {
  const context = {
    physicalUrl: 'https://appliance.example/',
    logicalUrl: 'https://appliance.example/dashboard',
    pageMarker: 'marker',
  };
  const tabs = installBridge(context);
  const projected = await tabs.query({ active: true, currentWindow: true });
  assert.equal(projected.length, 1);
  assert.equal(projected[0].id, 1);
  assert.equal(projected[0].url, context.logicalUrl);
});

test('page marker script serializes the marker safely', () => {
  const attributes = new Map<string, string>();
  vm.runInNewContext(buildBitwardenPageMarkerScript('quoted" marker\r\n'), {
    document: {
      documentElement: {
        setAttribute(name: string, value: string) {
          attributes.set(name, value);
        },
      },
    },
  });
  assert.equal(attributes.get('data-wormhole-bitwarden-active-tab'), 'quoted" marker\r\n');
});
