type CertificateNotice = {
  sessionId?: string;
  lifecycleId?: string;
  certificate?: { host: string; fingerprint: string };
};

export async function confirmRdpCertificate(
  notice: CertificateNotice,
  hooks: {
    available: () => boolean;
    prompt: (certificate: { host: string; fingerprint: string }) => Promise<boolean>;
    reply: (sessionId: string, lifecycleId: string, accepted: boolean) => Promise<void>;
  },
): Promise<void> {
  if (!notice.sessionId || !notice.lifecycleId) return;
  const certificate = notice.certificate;
  let accepted = false;
  if (
    hooks.available() &&
    certificate &&
    typeof certificate.host === 'string' &&
    certificate.host.length > 0 &&
    certificate.host.length <= 4096 &&
    typeof certificate.fingerprint === 'string' &&
    certificate.fingerprint.length > 0 &&
    certificate.fingerprint.length <= 4096
  ) {
    accepted = await hooks.prompt(certificate).catch(() => false);
    accepted = accepted && hooks.available();
  }
  await hooks.reply(notice.sessionId, notice.lifecycleId, accepted).catch(() => undefined);
}
