import { parseSharedCertificateRenewalRequest } from '../electron/vault-shared-setup-contract.ts';

type WorkspaceCAControls = {
  request: NonNullable<Window['wormhole']>['sharedWorkspaceCA'];
  reconnect: () => void;
  exportBundle?: NonNullable<Window['wormhole']>['exportSharedTLSBundle'];
  refreshKit?: NonNullable<Window['wormhole']>['refreshSharedRecoveryKit'];
};

export function mountSharedCertificateRenewal(
  container: HTMLElement,
  renew: NonNullable<Window['wormhole']>['renewSharedServerCertificate'],
  failed: () => void,
  rotation?: WorkspaceCAControls,
) {
  const details = document.createElement('details');
  details.className = 'shared-certificate-renewal';
  const title = document.createElement('summary');
  title.textContent = 'PostgreSQL server certificates';
  const form = document.createElement('form');
  form.className = 'startup-form';
  const label = document.createElement('label');
  label.textContent = 'Server CSR with the workspace’s approved DNS names and IP addresses';
  const input = document.createElement('textarea');
  input.maxLength = 32 * 1024;
  input.rows = 5;
  input.required = true;
  input.spellcheck = false;
  label.append(input);
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.className = 'startup-button startup-button-secondary';
  submit.textContent = 'Sign server CSR';
  const rotate = document.createElement('button');
  rotate.type = 'submit';
  rotate.className = submit.className;
  rotate.textContent = 'Stage a new workspace CA';
  rotate.hidden = true;
  const retire = document.createElement('button');
  retire.type = 'button';
  retire.className = submit.className;
  retire.textContent = 'Check installation and retire the previous CA';
  retire.hidden = true;
  const saveBundle = document.createElement('button');
  saveBundle.type = 'button';
  saveBundle.className = submit.className;
  saveBundle.textContent = 'Export signed trust bundle…';
  saveBundle.hidden = !rotation?.exportBundle;
  const refreshKit = document.createElement('button');
  refreshKit.type = 'button';
  refreshKit.className = submit.className;
  refreshKit.textContent = 'Update offline recovery kit…';
  refreshKit.hidden = true;
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  const certificate = document.createElement('label');
  certificate.textContent = 'Renewed server certificate (PEM)';
  certificate.hidden = true;
  const output = document.createElement('textarea');
  output.readOnly = true;
  output.spellcheck = false;
  output.rows = 5;
  certificate.append(output);
  form.append(label, submit, rotate, status, certificate, retire, saveBundle, refreshKit);
  details.append(title, form);
  container.append(details);
  let disposed = false;
  const setBusy = (busy: boolean) => {
    submit.disabled =
      rotate.disabled =
      retire.disabled =
      saveBundle.disabled =
      refreshKit.disabled =
      input.disabled =
        busy;
  };
  details.ontoggle = async () => {
    if (!rotation || !details.open || disposed || submit.disabled) return;
    setBusy(true);
    try {
      const result = await rotation.request({ action: 'status' });
      if (disposed) return;
      const staged = result.status === 'staged';
      rotate.hidden = result.status !== 'ready';
      refreshKit.hidden = result.status !== 'ready' || !rotation.refreshKit;
      retire.hidden = !staged;
      label.hidden = submit.hidden = staged;
      if (staged) {
        certificate.hidden = false;
        output.value = result.serverPem;
        status.textContent =
          'Both CAs are trusted. Let enrolled devices receive the update, or export it for offline devices. Then install this certificate and reload PostgreSQL.';
      }
    } catch {
      if (!disposed) failed();
    } finally {
      if (!disposed) setBusy(false);
    }
  };
  retire.onclick = async () => {
    if (!rotation || disposed || retire.hidden || retire.disabled) return;
    setBusy(true);
    try {
      const result = await rotation.request({ action: 'retire' });
      if (disposed) return;
      if (result.status === 'retired') rotation.reconnect();
      else
        status.textContent =
          result.status === 'installation-required'
            ? 'PostgreSQL must serve the staged certificate on every configured endpoint.'
            : 'Retiring the previous CA requires an administrator with access to the issuing CA.';
    } catch {
      if (!disposed) failed();
    } finally {
      if (!disposed) setBusy(false);
    }
  };
  saveBundle.onclick = async () => {
    if (!rotation?.exportBundle || disposed || saveBundle.disabled) return;
    setBusy(true);
    try {
      const result = await rotation.exportBundle();
      if (disposed || result === null) return;
      status.textContent = result
        ? 'Signed trust bundle saved.'
        : 'Could not save the trust bundle. Choose a new file.';
    } catch {
      if (!disposed) failed();
    } finally {
      if (!disposed) setBusy(false);
    }
  };
  refreshKit.onclick = async () => {
    if (!rotation?.refreshKit || disposed || refreshKit.hidden || refreshKit.disabled) return;
    setBusy(true);
    try {
      const result = await rotation.refreshKit();
      if (disposed || result === null) return;
      const feedback = {
        updated: 'Updated kit saved. Keep it with your existing recovery code.',
        unavailable: 'Updating this kit requires an administrator with access to the issuing CA.',
        'invalid-kit': 'Choose the original recovery kit for this workspace.',
        'save-failed': 'Could not save the updated kit. Choose a new file.',
      };
      status.textContent = feedback[result];
    } catch {
      if (!disposed) failed();
    } finally {
      if (!disposed) setBusy(false);
    }
  };
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (disposed || submit.hidden || submit.disabled) return;
    certificate.hidden = true;
    output.value = '';
    const request = parseSharedCertificateRenewalRequest({ csr: input.value.trim() });
    if (!request) {
      input.value = '';
      status.textContent = 'Paste a PEM certificate signing request.';
      return;
    }
    const staging = event.submitter === rotate && rotation && !rotate.hidden;
    setBusy(true);
    status.textContent = staging ? 'Staging the new workspace CA…' : 'Signing the server CSR…';
    try {
      if (staging) {
        const result = await rotation.request({ action: 'rotate', csr: request.csr });
        if (disposed) return;
        if (result.status === 'staged') rotation.reconnect();
        else
          status.textContent =
            result.status === 'invalid-csr'
              ? 'Check the CSR and workspace host names.'
              : 'CA rotation requires an administrator with access to the issuing CA.';
        return;
      }
      const result = await renew(request);
      if (disposed) return;
      if (result.status === 'issued') {
        output.value = result.serverPem;
        certificate.hidden = false;
        status.textContent =
          'Install this certificate on PostgreSQL and reload its TLS configuration.';
      } else if (result.status === 'invalid-csr') {
        status.textContent =
          'Could not issue the certificate. Check the CSR and that the workspace CA is still valid.';
      } else {
        status.textContent =
          'Renewal requires an administrator with access to the workspace issuing CA.';
      }
    } catch {
      if (!disposed) failed();
    } finally {
      if (!disposed) setBusy(false);
    }
  };
  return () => {
    disposed = true;
    form.onsubmit = null;
    details.ontoggle = retire.onclick = saveBundle.onclick = refreshKit.onclick = null;
    input.value = output.value = '';
    details.remove();
  };
}
