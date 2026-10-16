import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Download, LoaderCircle, ShieldCheck } from 'lucide-react';
import { describeError } from '../api/client';
import type { TotpSetup } from '../api/types';
import { useT } from '../i18n';
import { Copy, Field, Loading } from './ui';

/** The input of a 6-digit code (or a recovery code when `recovery`). */
export function CodeInput({ value, onChange, recovery, autoFocus = true }: { value: string; onChange: (v: string) => void; recovery?: boolean; autoFocus?: boolean }) {
  const t = useT();
  return (
    <input
      className="input code-input"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      inputMode={recovery ? 'text' : 'numeric'}
      autoComplete="one-time-code"
      maxLength={recovery ? 16 : 8}
      placeholder={recovery ? 'xxxxx-xxxxx' : '123456'}
      autoFocus={autoFocus}
      spellCheck={false}
      aria-label={recovery ? t('Recovery code') : t('Code from the app')}
    />
  );
}

/**
 * Setting up an authenticator app: `begin` makes a new secret (QR code and the key to type), `confirm` turns it on
 * with the first code. Used on the profile page and during the sign-in when the policy requires a second factor.
 */
export function TotpSetupForm({ begin, confirm, onCancel, submitLabel }: { begin: () => Promise<TotpSetup>; confirm: (code: string) => Promise<void>; onCancel?: () => void; submitLabel: string }) {
  const t = useT();
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);
  useEffect(() => {
    // once: every call makes a new secret (and React runs effects twice in development)
    if (started.current) return;
    started.current = true;
    begin()
      .then(setSetup)
      .catch((e) => setError(describeError(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await confirm(code);
    } catch (err) {
      setError(describeError(err));
      setBusy(false);
    }
  };
  return (
    <form className="stack totp-setup" style={{ gap: 14 }} onSubmit={submit}>
      {error && (
        <div className="notice notice-error" role="alert">
          {error}
        </div>
      )}
      <ol className="totp-steps">
        <li>{t('Install an authenticator app on your phone: Google Authenticator, Microsoft Authenticator, 1Password, Aegis or another.')}</li>
        <li>{t('Scan the QR code with the app, or type the key by hand.')}</li>
        <li>{t('Enter the 6-digit code the app shows.')}</li>
      </ol>
      {!setup ? (
        !error && <Loading />
      ) : (
        <div className="totp-qr-row">
          <img className="totp-qr" src={setup.qr} alt={t('QR code for the authenticator app')} width={180} height={180} />
          <div className="stack" style={{ gap: 6, minWidth: 0 }}>
            <span className="hint">{t('Key')}</span>
            <div className="key-box totp-key">{setup.secret.replace(/(.{4})/g, '$1 ').trim()}</div>
            <div>
              <Copy value={setup.secret} label={t('Copy the key')} />
            </div>
            <span className="hint">{t('Time-based, 6 digits, every 30 seconds')}</span>
          </div>
        </div>
      )}
      <Field label={t('Code from the app')}>
        <CodeInput value={code} onChange={setCode} autoFocus={false} />
      </Field>
      <div className="row-end">
        {onCancel && (
          <button type="button" className="btn" onClick={onCancel}>
            {t('Cancel')}
          </button>
        )}
        <button className="btn btn-primary" type="submit" disabled={busy || !setup || code.replace(/\D/g, '').length < 6}>
          {busy ? <LoaderCircle size={16} className="spin" /> : <ShieldCheck size={16} />}
          {submitLabel}
        </button>
      </div>
    </form>
  );
}

/** Recovery codes, shown once after they are made. */
export function RecoveryCodes({ codes, username }: { codes: string[]; username: string }) {
  const t = useT();
  const text = `${t('Recovery codes of {user}', { user: username })}\n\n${codes.join('\n')}\n`;
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'spa-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="stack" style={{ gap: 12 }}>
      <div className="notice notice-warning">{t('Save these recovery codes somewhere safe. Each one signs you in once if you lose your phone. They are shown only now.')}</div>
      <ul className="recovery-codes">
        {codes.map((c) => (
          <li key={c} className="mono">
            {c}
          </li>
        ))}
      </ul>
      <div className="row-end">
        <Copy value={codes.join('\n')} label={t('Copy the codes')} />
        <button type="button" className="btn btn-sm" onClick={download}>
          <Download size={14} />
          {t('Download')}
        </button>
      </div>
    </div>
  );
}
