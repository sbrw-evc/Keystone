import { useEffect, useState } from 'react';
import { KeyRound, LoaderCircle } from 'lucide-react';
import { get, post, put } from '../api/client';
import type { General } from '../api/types';
import { Confirm, ErrorNotice, Field, Loading, PageHead, Switch } from '../components/ui';
import { useT } from '../i18n';
import { isAdmin, useAuth, useLoad } from '../lib/auth';
import { toast } from '../lib/toast';

export function GeneralPage() {
  const t = useT();
  const { account } = useAuth();
  const admin = isAdmin(account);
  const { data, error, setData } = useLoad(() => get<General>('/api/v1/settings/general'));
  const [v, setV] = useState<General | null>(null);
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [rotate, setRotate] = useState(false);
  useEffect(() => {
    if (data) setV(data);
  }, [data]);
  if (!v) return error ? <ErrorNotice error={error} /> : <Loading />;
  const ro = !admin;
  const save = async () => {
    setBusy(true);
    setSaveError(null);
    try {
      setData(await put<General>('/api/v1/settings/general', { general: v.general, passkeys: v.passkeys }));
      toast(t('Saved'));
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <PageHead
        title={t('General')}
        subtitle={t('How Keystone presents itself, passkeys and the signing key of its tokens.')}
        actions={
          admin && (
            <button type="button" className="btn btn-primary" onClick={save} disabled={busy}>
              {busy && <LoaderCircle size={16} className="spin" />}
              {t('Save')}
            </button>
          )
        }
      />
      <ErrorNotice error={saveError} />
      <section className="card">
        <div className="card-head">
          <h2>{t('Keystone')}</h2>
        </div>
        <div className="card-body">
          <dl className="kv">
            <dt>{t('Issuer (public address)')}</dt>
            <dd>
              <code>{v.issuer}</code> {!v.public_url_set && <span className="pill pill-warn">{t('SPA_PUBLIC_URL is not set')}</span>}
            </dd>
            <dt>{t('Discovery')}</dt>
            <dd>
              <a href="/.well-known/openid-configuration" target="_blank" rel="noreferrer">
                /.well-known/openid-configuration
              </a>
            </dd>
            <dt>{t('Secrets are kept in')}</dt>
            <dd>{v.secrets === 'openbao' ? 'OpenBao' : t('the database, sealed with SPA_MASTER_KEY')}</dd>
          </dl>
          <Field label={t('Organization')} hint={t('Shown on the sign-in page')}>
            <input className="input" value={v.general.organization} disabled={ro} onChange={(e) => setV({ ...v, general: { ...v.general, organization: e.target.value } })} />
          </Field>
          <Switch
            checked={v.general.allow_local}
            disabled={ro}
            onChange={(x) => setV({ ...v, general: { ...v.general, allow_local: x } })}
            label={t('Local accounts may sign in with a password')}
            hint={t('Turn off when everyone comes from a directory or a provider. Keystone administrators can always sign in with a password.')}
          />
        </div>
      </section>
      <section className="card">
        <div className="card-head">
          <h2>{t('Passkeys')}</h2>
        </div>
        <div className="card-body">
          <Switch checked={v.passkeys.enabled} disabled={ro} onChange={(x) => setV({ ...v, passkeys: { ...v.passkeys, enabled: x } })} label={t('Passkeys are allowed')} hint={t('Windows Hello, Touch ID, Face ID, Android and security keys')} />
          <Field label={t('Passkey domain')} hint={t('Empty — the host name of Keystone. A parent domain keeps passkeys working when Keystone moves between its subdomains.')}>
            <input className="input mono" value={v.passkeys.rp_id} disabled={ro} onChange={(e) => setV({ ...v, passkeys: { ...v.passkeys, rp_id: e.target.value } })} placeholder="example.com" />
          </Field>
        </div>
      </section>
      <section className="card">
        <div className="card-head">
          <div>
            <h2>
              <KeyRound size={18} />
              {t('Signing key')}
            </h2>
            <p className="muted">{t('Keystone signs ID tokens with an RSA key from its secret store. The JWKS lists the current and the previous key, so tokens signed before a rotation still verify.')}</p>
          </div>
          {admin && (
            <button type="button" className="btn" onClick={() => setRotate(true)}>
              {t('Rotate the signing key')}
            </button>
          )}
        </div>
        <div className="card-body">
          <a href="/oauth2/jwks" target="_blank" rel="noreferrer">
            /oauth2/jwks
          </a>
        </div>
      </section>
      {rotate && (
        <Confirm
          title={t('Rotate the signing key?')}
          text={t('A new key signs tokens from now on. The previous key stays in the JWKS; the one before it is dropped.')}
          confirm={t('Rotate')}
          onClose={() => setRotate(false)}
          onConfirm={async () => {
            await post('/api/v1/settings/signing-key/rotate');
            toast(t('The signing key is rotated'));
          }}
        />
      )}
    </>
  );
}
