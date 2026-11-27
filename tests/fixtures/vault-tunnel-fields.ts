import { mountVaultTunnelFields } from '../../src/vault-tunnel-fields';
import { vaultTunnelFields } from '../../src/vault-tunnel-form';
import { tunnelDefaultSettings } from '../../src/tunnel-editor-schema';
declare const assert: typeof import('node:assert/strict');

export function runVaultTunnelFieldTests() {
  const card = document.getElementById('root')!;
  let changes = 0;
  const references = {
    tunnels: [{ id: 'ssl', name: 'SSL VPN' }],
    connections: [{ id: 'connection', name: 'Connection <img src=x>' }],
    credentials: [{ id: 'credential', name: 'SSH account' }],
  };
  function setup(
    kind: number,
    settings: Record<string, any> = {},
    present: string[] = [],
    draft = false,
  ) {
    const fields = mountVaultTunnelFields(
      card,
      { name: 'Tunnel', kind, settings, present },
      references,
      draft,
      () => changes++,
    );
    const row = (key: string) => card.querySelector<HTMLElement>(`[data-field="${key}"]`)!;
    const input = (key: string) =>
      row(key).querySelector<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(
        `[name="${key}"]`,
      )!;
    const mode = (key: string) => row(key).querySelector<HTMLSelectElement>('select')!;
    const set = (key: string, value: string | boolean) => {
      const element = input(key);
      if (typeof value === 'boolean') (element as HTMLInputElement).checked = value;
      else element.value = value;
      element.dispatchEvent(new Event('input', { bubbles: true }));
    };
    const secret = (key: string, action: string, value = '') => {
      mode(key).value = action;
      mode(key).dispatchEvent(new Event('change'));
      input(key).value = value;
    };
    const patch = () => {
      const { patch, forgetHostKey } = fields.serialize();
      try {
        return { value: JSON.parse(new TextDecoder().decode(patch)), forgetHostKey };
      } finally {
        patch.fill(0);
      }
    };
    return { ...fields, row, input, mode, set, secret, patch };
  }
  for (let kind = 0; kind < 9; kind++) {
    const secretKeys = vaultTunnelFields(kind)
      .filter((f) => f.secret)
      .map((f) => f.key);
    const f = setup(kind, tunnelDefaultSettings(kind), secretKeys, true);
    for (const field of vaultTunnelFields(kind)) {
      assert.equal(f.row(field.key).querySelector('label')!.textContent, field.label);
      if (field.secret) {
        assert.equal(f.input(field.key).value, '');
        assert.equal(f.input(field.key).disabled, true);
        assert.equal(f.input(field.key).hidden, true);
        assert.match(f.mode(field.key).textContent!, /Keep stored value/);
      }
    }
    const value = f.patch().value;
    for (const key of secretKeys) assert.equal(value[key], undefined);
    f.dispose();
    assert.equal(card.childElementCount, 0);
  }
  let f = setup(1, { Username: 'original' }, ['ProfileOvpn', 'Password']);
  assert.deepEqual(f.patch().value, {});
  assert.equal(f.input('ProfileOvpn').getAttribute('value'), null);
  f.set('Username', 'changed');
  assert.deepEqual(f.patch().value, { Username: 'changed' });
  f.secret('Password', 'replace', 'new-password');
  assert.equal(f.patch().value.Password, 'new-password');
  f.clearSubmitted();
  assert.equal(f.input('Password').value, '');
  assert.throws(() => f.patch(), /Enter password again/);
  f.secret('Password', 'keep');
  f.secret('ProfileOvpn', 'remove');
  assert.equal(f.patch().value.ProfileOvpn, null);
  f.secret('ProfileOvpn', 'replace', 'private profile');
  const retained = f.input('ProfileOvpn');
  f.dispose();
  f.dispose();
  assert.equal(retained.value, '');
  assert.equal(retained.oninput, null);
  assert.throws(() => f.serialize(), /closed/);

  f = setup(
    2,
    {
      Host: 'gateway',
      Port: 443,
      UseSingleSignOn: false,
      UseExternalBrowser: true,
      Realm: '',
      SamlRedirectPort: 8020,
    },
    ['Password', 'TotpSecret'],
  );
  assert.equal(f.row('UseExternalBrowser'), null);
  assert.equal(f.row('SamlRedirectPort'), null);
  f.secret('Password', 'replace', 'must-clear');
  f.set('UseSingleSignOn', true);
  assert.equal(f.input('Password').value, '');
  assert.equal(f.row('Password').hidden, true);
  assert.equal(getComputedStyle(f.row('Password')).display, 'none');
  assert.equal(f.input('Realm').disabled, false);
  f.set('Realm', 'staff');
  assert.equal(f.patch().value.Realm, 'staff');
  f.set('UseSingleSignOn', false);
  assert.equal(f.row('Password').hidden, false);
  assert.throws(() => f.patch(), /again/);
  f.secret('Password', 'keep');
  f.set('Port', '443.5');
  assert.throws(() => f.patch(), /whole number/);
  f.set('Port', '');
  assert.equal(f.patch().value.Port, null);
  f.set('Host', '');
  assert.equal(f.patch().value.Host, null);
  f.dispose();

  for (const settings of [
    { UseSingleSignOn: true, AuthMode: 1 },
    { UseSingleSignOn: false },
    { AuthMode: 2 },
    { Username: 'alice' },
  ]) {
    f = setup(3, settings, settings.Username ? ['Password'] : []);
    const expected = settings.UseSingleSignOn === true || settings.AuthMode === 2 ? '2' : '1';
    assert.equal(f.input('AuthMode').value, expected);
    assert.equal(f.row('Username').hidden, expected === '2');
    f.set('AuthMode', '1');
    f.secret('Password', 'replace', 'replacement');
    assert.equal(f.patch().value.AuthMode, 1);
    f.set('AuthMode', '2');
    assert.equal(f.input('Password').value, '');
    assert.equal(f.patch().value.Password, undefined);
    f.dispose();
  }
  f = setup(3, {}, ['ClientKeyPem']);
  assert.equal(f.input('AuthMode').value, '1');
  f.dispose();
  f = setup(3, {}, []);
  assert.equal(f.input('AuthMode').value, '2');
  f.dispose();
  f = setup(4, {}, ['ProfileOvpn']);
  assert.equal(f.input('Mode').value, '1');
  assert.equal(f.row('ProfileOvpn').hidden, false);
  f.secret('ProfileOvpn', 'replace', 'secret-profile');
  f.set('Mode', '0');
  assert.equal(f.input('ProfileOvpn').value, '');
  assert.equal(f.row('ProfileOvpn').hidden, true);
  f.dispose();
  f = setup(4, { Mode: 1 }, ['ProfileOvpn']);
  f.secret('ProfileOvpn', 'remove');
  f.set('Mode', '0');
  assert.equal(f.patch().value.ProfileOvpn, null);
  f.dispose();
  f = setup(4, {}, []);
  assert.equal(f.input('Mode').value, '0');
  f.dispose();

  f = setup(8, {
    Mode: 'manual',
    Host: 'jump',
    Username: 'alice',
    CredentialId: 'unavailable',
    HostKeySha256: 'SHA256:pin',
    KeepaliveSeconds: 30,
  });
  assert.equal(f.input('Port').value, '22');
  assert.match(f.input('CredentialId').textContent!, /Unavailable saved selection/);
  assert.equal(card.querySelector('img'), null);
  const forget = card.querySelector<HTMLInputElement>('.vault-tunnel-pin input')!;
  forget.checked = true;
  forget.dispatchEvent(new Event('change'));
  assert.equal(f.patch().forgetHostKey, true);
  f.set('Mode', 'connection');
  assert.equal(forget.checked, false);
  assert.equal(f.row('Host').hidden, true);
  f.set('JumpConnectionId', 'connection');
  assert.deepEqual(f.patch().value, { Mode: 'connection', JumpConnectionId: 'connection' });
  f.set('Mode', 'manual');
  assert.equal(f.patch().value.Port, 22);
  assert.equal(f.patch().value.JumpConnectionId, undefined);
  f.dispose();

  f = setup(0, { Dns: ['1.1.1.1', '2.2.2.2'], AllowedIps: ['0.0.0.0/0'] });
  assert.equal(f.input('Dns').value, '1.1.1.1, 2.2.2.2');
  assert.deepEqual(f.patch().value, {});
  f.set('Dns', '9.9.9.9');
  assert.equal(f.patch().value.Dns, '9.9.9.9');
  f.dispose();
  f = setup(1);
  f.secret('ProfileOvpn', 'replace', '😀'.repeat(1024 * 1024));
  assert.throws(() => f.serialize(), /too large/);
  f.clearSubmitted();
  f.dispose();
  assert.ok(changes > 0);
  const ipsec = setup(
    9,
    { Host: 'vpn.test', UserAuth: 2, AuthMethod: 0 },
    ['PreSharedKey', 'Password'],
    false,
  );
  assert.equal(ipsec.input('Password').value, '');
  ipsec.secret('PreSharedKey', 'replace', 'temporary-psk');
  ipsec.secret('Password', 'replace', 'temporary-password');
  ipsec.set('AuthMethod', '1');
  assert.ok(ipsec.row('PreSharedKey').hidden);
  assert.equal(ipsec.input('PreSharedKey').value, '');
  assert.equal(ipsec.row('ClientKey').hidden, false);
  ipsec.secret('ClientKey', 'replace', 'temporary-private-key');
  ipsec.set('AuthMethod', '0');
  assert.equal(ipsec.input('ClientKey').value, '');
  ipsec.set('UserAuth', '3');
  assert.equal(ipsec.input('Password').value, '');
  assert.ok(ipsec.row('Username').hidden);
  ipsec.set('IkeVersion', '1');
  assert.equal(ipsec.row('ExchangeMode').hidden, false);
  ipsec.set('AddressAssignment', '1');
  assert.equal(ipsec.row('ManualAddress').hidden, false);
  ipsec.set('Pfs', true);
  assert.equal(ipsec.row('PfsGroup').hidden, false);
  ipsec.set('Phase2ByteLifetime', true);
  assert.equal(ipsec.row('Phase2LifetimeKb').hidden, false);
  assert.equal(ipsec.input('FallbackTunnelId').querySelectorAll('option').length, 2);
  ipsec.dispose();
  const legacyIpsec = setup(9, {}, ['PreSharedKey']);
  assert.equal(legacyIpsec.input('UserAuth').value, '3');
  assert.equal((legacyIpsec.input('AutoProposals') as HTMLInputElement).checked, true);
  legacyIpsec.dispose();
  // Keep one real provider mounted for the screenshot and layout checks.
  f = setup(
    2,
    {
      Host: 'vpn.example.com',
      Port: 443,
      UseSingleSignOn: false,
      UseExternalBrowser: true,
      SamlRedirectPort: 8020,
    },
    ['Password'],
  );
  assert.ok(card.scrollWidth <= card.clientWidth);
  return f.dispose;
}
