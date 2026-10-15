import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { AppWindow, Check, Fingerprint, KeyRound, LoaderCircle, X } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ApiError, describeError, get, post } from '../api/client';
import type { Account, PasswordPolicy, SignedIn, SignInMethods } from '../api/types';
import { Avatar, Brand, Field, Loading, PasswordInput, Preferences, ProviderMark } from '../components/ui';
import { useT, type TFn } from '../i18n';
import { useAuth } from '../lib/auth';
import { getAssertion, passkeysSupported } from '../lib/webauthn';

const SSO = ['entra', 'google', 'apple', 'oidc'];

/** The rules of the password policy that can be checked in the browser, with their state for a password. */
export function policyRules(p: PasswordPolicy, pw: string, t: TFn) {
  const digits = (pw.match(/\p{Nd}/gu) ?? []).length;
  const special = (pw.match(/[^\p{L}\p{Nd}\s]/gu) ?? []).length;
  const rules = [{ ok: [...pw].length >= p.min_length, text: t('At least {n} characters', { n: p.min_length }) }];
  if (p.require_digits) rules.push({ ok: digits >= p.min_digits, text: t('Digits: at least {n}', { n: p.min_digits }) });
  if (p.require_special) rules.push({ ok: special >= p.min_special, text: t('Special characters: at least {n}', { n: p.min_special }) });
  if (p.require_mixed_case) rules.push({ ok: /\p{Lu}/u.test(pw) && /\p{Ll}/u.test(pw), text: t('Upper- and lower-case letters') });
  return rules;
}

export function PolicyRules({ policy, password }: { policy: PasswordPolicy; password: string }) {
  const t = useT();
  return (
    <ul className="rules">
      {policyRules(policy, password, t).map((r) => (
        <li key={r.text} className={password ? (r.ok ? 'ok' : 'bad') : ''}>
          {r.ok ? <Check size={14} /> : <X size={14} />}
          {r.text}
        </li>
      ))}
      {policy.block_common && <li>{t('Not a common or easily guessed password')}</li>}
      {policy.history_count > 0 && <li>{t('Not one of your last {n} passwords', { n: policy.history_count })}</li>}
    </ul>
  );
}

function go(next: string) {
  window.location.assign(next || '/');
}

export function SignInPage() {
  const t = useT();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { account, loading: authLoading } = useAuth();
  const request = params.get('request') ?? '';
  const appName = params.get('app') ?? '';
  const ret = params.get('return') ?? '';
  const hint = params.get('method') ?? '';
  const [info, setInfo] = useState<SignInMethods | null>(null);
  const [username, setUsername] = useState(params.get('login_hint') ?? '');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(params.get('error'));
  const [change, setChange] = useState<{ ticket: string; expired: boolean } | null>(null);
  const [another, setAnother] = useState(false);

  useEffect(() => {
    get<SignInMethods>('/api/v1/auth/methods')
      .then(setInfo)
      .catch((e) => setError(describeError(e)));
  }, []);

  // Already signed in: into SPA at once; for an application the person confirms (or picks another account).
  useEffect(() => {
    if (!authLoading && account && !request) navigate(ret.startsWith('/') && !ret.startsWith('//') ? ret : '/', { replace: true });
  }, [authLoading, account, request, ret, navigate]);

  const methods = info?.methods ?? [];
  const has = (id: string) => methods.some((m) => m.id === id);
  const sso = methods.filter((m) => SSO.includes(m.id));
  const passwordForm = has('password') || has('ldap');
  const ssoQuery = useMemo(() => {
    const q = new URLSearchParams();
    if (request) q.set('request', request);
    if (ret) q.set('return', ret);
    const s = q.toString();
    return s ? `?${s}` : '';
  }, [request, ret]);

  // idp_hint of the application: go straight to the provider.
  useEffect(() => {
    if (info && SSO.includes(hint) && has(hint) && !params.get('error') && !account) window.location.assign(`/api/v1/auth/sso/${hint}/start${ssoQuery}`);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [info, hint]);

  const signIn = async (e: FormEvent) => {
    e.preventDefault();
    setBusy('password');
    setError(null);
    try {
      const res = await post<SignedIn>('/api/v1/auth/password', { username, password, request, return: ret });
      go(res.next);
    } catch (err) {
      if (err instanceof ApiError && err.code === 'password_change_required') {
        setChange({ ticket: String(err.extra.ticket ?? ''), expired: !!err.extra.expired });
      } else setError(describeError(err));
      setBusy(null);
    }
  };

  const passkey = async () => {
    setBusy('passkey');
    setError(null);
    try {
      const begun = await post<{ ceremony: string; options: { publicKey: Record<string, unknown> } }>('/api/v1/auth/passkey/begin');
      const credential = await getAssertion(begun.options);
      const res = await post<SignedIn>('/api/v1/auth/passkey/finish', { ceremony: begun.ceremony, credential, request, return: ret });
      go(res.next);
    } catch (err) {
      setError(describeError(err));
      setBusy(null);
    }
  };

  const proceed = async () => {
    setBusy('continue');
    setError(null);
    try {
      const res = await post<{ next: string }>('/api/v1/auth/continue', { request });
      go(res.next);
    } catch (err) {
      setError(describeError(err));
      setBusy(null);
    }
  };

  const org = info?.organization;
  return (
    <div className="center-page">
      <div className="card signin-card">
        <div className="signin-top">
          <Brand />
          <Preferences />
        </div>
        {!info && !error ? (
          <Loading />
        ) : change ? (
          <ChangeExpired ticket={change.ticket} expired={change.expired} policy={info!.password_policy} username={username} onCancel={() => setChange(null)} />
        ) : (
          <>
            <div className="signin-title">
              <h1>{t('Sign in')}</h1>
              <p className="muted">{org ? t('to {org}', { org }) : t('Single Point of Authorization')}</p>
            </div>
            <div className="signin-form">
              {appName && (
                <div className="app-request">
                  <AppWindow size={18} />
                  <span>{t('{app} asks you to sign in', { app: appName })}</span>
                </div>
              )}
              {params.get('signed_out') && !error && <div className="notice notice-success">{t('You have signed out')}</div>}
              {error && (
                <div className="notice notice-error" role="alert">
                  {t(error)}
                </div>
              )}
              {account && request && !another ? (
                <ContinueAs account={account} busy={busy === 'continue'} onContinue={proceed} onAnother={() => setAnother(true)} />
              ) : (
                <>
                  {passwordForm && (
                    <form className="signin-form" style={{ marginTop: 0 }} onSubmit={signIn}>
                      <Field label={t('User name')} hint={has('ldap') ? t('Your {dir} account works too', { dir: methods.find((m) => m.id === 'ldap')!.title }) : undefined}>
                        <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username webauthn" autoFocus={!username} />
                      </Field>
                      <Field label={t('Password')}>
                        <PasswordInput value={password} onChange={setPassword} autoComplete="current-password" autoFocus={!!username} />
                      </Field>
                      <button className="btn btn-primary btn-block" type="submit" disabled={!!busy || !username || !password}>
                        {busy === 'password' ? <LoaderCircle size={16} className="spin" /> : <KeyRound size={16} />}
                        {t('Sign in')}
                      </button>
                    </form>
                  )}
                  {(has('passkey') || sso.length > 0) && passwordForm && <div className="or">{t('or')}</div>}
                  <div className="sso-list">
                    {has('passkey') && passkeysSupported() && (
                      <button type="button" className={`btn btn-block sso-btn ${hint === 'passkey' ? 'btn-primary' : ''}`} onClick={passkey} disabled={!!busy}>
                        <span className="sso-logo">{busy === 'passkey' ? <LoaderCircle size={18} className="spin" /> : <Fingerprint size={18} />}</span>
                        <span>{t('Sign in with a passkey')}</span>
                      </button>
                    )}
                    {sso.map((m) => (
                      <a key={m.id} className="btn btn-block sso-btn" href={`/api/v1/auth/sso/${m.id}/start${ssoQuery}`}>
                        <span className="sso-logo">
                          <ProviderMark kind={m.id} />
                        </span>
                        <span>{t('Continue with {name}', { name: m.title })}</span>
                      </a>
                    ))}
                  </div>
                  {!methods.length && info && <div className="notice notice-warning">{t('No sign-in method is turned on. Ask an administrator')}</div>}
                </>
              )}
            </div>
          </>
        )}
      </div>
      <p className="signin-foot">{t('One account for every Umbrella application')}</p>
    </div>
  );
}

function ContinueAs({ account, busy, onContinue, onAnother }: { account: Account; busy: boolean; onContinue: () => void; onAnother: () => void }) {
  const t = useT();
  const name = account.name || account.username;
  return (
    <div className="stack" style={{ gap: 12 }}>
      <div className="cell-main card card-pad" style={{ boxShadow: 'none' }}>
        <Avatar name={name} size={40} />
        <div>
          <strong>{name}</strong>
          <small>{account.email || account.username}</small>
        </div>
      </div>
      <button type="button" className="btn btn-primary btn-block" onClick={onContinue} disabled={busy}>
        {busy && <LoaderCircle size={16} className="spin" />}
        {t('Continue as {name}', { name })}
      </button>
      <button type="button" className="btn btn-ghost btn-block" onClick={onAnother}>
        {t('Use another account')}
      </button>
    </div>
  );
}

/** A password that expired (or was set by an administrator) is changed before the sign-in finishes. */
function ChangeExpired({ ticket, expired, policy, username, onCancel }: { ticket: string; expired: boolean; policy: PasswordPolicy; username: string; onCancel: () => void }) {
  const t = useT();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (next !== repeat) {
      setError(t('The new passwords do not match'));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await post<SignedIn>('/api/v1/auth/password/change', { ticket, current, new: next });
      go(res.next);
    } catch (err) {
      setError(describeError(err));
      setBusy(false);
    }
  };
  return (
    <>
      <div className="signin-title">
        <h1>{t('Choose a new password')}</h1>
        <p className="muted">{expired ? t('The password of {user} has expired.', { user: username }) : t('The password of {user} must be changed at the first sign-in.', { user: username })}</p>
      </div>
      <form className="signin-form" onSubmit={submit}>
        {error && <div className="notice notice-error">{error}</div>}
        <Field label={t('Current password')}>
          <PasswordInput value={current} onChange={setCurrent} autoComplete="current-password" autoFocus />
        </Field>
        <Field label={t('New password')}>
          <PasswordInput value={next} onChange={setNext} autoComplete="new-password" />
        </Field>
        <PolicyRules policy={policy} password={next} />
        <Field label={t('Repeat the new password')}>
          <PasswordInput value={repeat} onChange={setRepeat} autoComplete="new-password" />
        </Field>
        <button className="btn btn-primary btn-block" type="submit" disabled={busy || !current || !next}>
          {busy && <LoaderCircle size={16} className="spin" />}
          {t('Change password and sign in')}
        </button>
        <button type="button" className="btn btn-ghost btn-block" onClick={onCancel}>
          {t('Back')}
        </button>
      </form>
    </>
  );
}
