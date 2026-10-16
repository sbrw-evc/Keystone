import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { AppWindow, Check, Fingerprint, KeyRound, LoaderCircle, ShieldCheck, X } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ApiError, describeError, get, post } from '../api/client';
import type { Account, PasswordPolicy, SignedIn, SignInMethods, TotpSetup } from '../api/types';
import { CodeInput, RecoveryCodes, TotpSetupForm } from '../components/totp';
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

/** The steps after a right password: a new password, the code of the authenticator app, setting one up, the recovery codes. */
type Step =
  | { kind: 'change'; ticket: string; expired: boolean }
  | { kind: 'totp'; ticket: string }
  | { kind: 'setup'; ticket: string }
  | { kind: 'codes'; codes: string[]; next: string };

/** The step an answer of the sign-in asks for, if it asks for one. */
function stepOf(err: unknown): Step | null {
  if (!(err instanceof ApiError)) return null;
  const ticket = String(err.extra.ticket ?? '');
  switch (err.code) {
    case 'password_change_required':
      return { kind: 'change', ticket, expired: !!err.extra.expired };
    case 'totp_required':
      return { kind: 'totp', ticket };
    case 'totp_setup_required':
      return { kind: 'setup', ticket };
  }
  return null;
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
  const [step, setStep] = useState<Step | null>(null);
  /** Goes on after an answer of a sign-in step: the next step, the recovery codes, or where the sign-in leads. */
  const finish = (res: SignedIn) => (res.recovery_codes?.length ? setStep({ kind: 'codes', codes: res.recovery_codes, next: res.next }) : go(res.next));
  const next = (err: unknown) => {
    const s = stepOf(err);
    if (s) setStep(s);
    return !!s;
  };
  const [another, setAnother] = useState(false);

  useEffect(() => {
    get<SignInMethods>('/api/v1/auth/methods')
      .then(setInfo)
      .catch((e) => setError(describeError(e)));
  }, []);

  // Already signed in: into Keystone at once; for an application the person confirms (or picks another account).
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
      finish(await post<SignedIn>('/api/v1/auth/password', { username, password, request, return: ret }));
    } catch (err) {
      if (!next(err)) setError(describeError(err));
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
        ) : step?.kind === 'change' ? (
          <ChangeExpired key={step.ticket} ticket={step.ticket} expired={step.expired} policy={info!.password_policy} username={username} onDone={finish} onNext={next} onCancel={() => setStep(null)} />
        ) : step?.kind === 'totp' ? (
          <TotpStep key={step.ticket} ticket={step.ticket} onDone={finish} onNext={next} onCancel={() => setStep(null)} />
        ) : step?.kind === 'setup' ? (
          <SetupStep key={step.ticket} ticket={step.ticket} username={username} onDone={finish} onNext={next} onCancel={() => setStep(null)} />
        ) : step?.kind === 'codes' ? (
          <CodesStep codes={step.codes} next={step.next} username={username} />
        ) : (
          <>
            <div className="signin-title">
              <h1>{t('Sign in')}</h1>
              <p className="muted">{org ? t('to {org}', { org }) : t('Sign-in and access for the Umbrella family')}</p>
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
type StepProps = { ticket: string; onDone: (res: SignedIn) => void; onNext: (err: unknown) => boolean; onCancel: () => void };

function ChangeExpired({ ticket, expired, policy, username, onDone, onNext, onCancel }: StepProps & { expired: boolean; policy: PasswordPolicy; username: string }) {
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
      onDone(await post<SignedIn>('/api/v1/auth/password/change', { ticket, current, new: next }));
    } catch (err) {
      if (!onNext(err)) setError(describeError(err));
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

/** The code of the authenticator app (or a recovery code) after the password. */
function TotpStep({ ticket, onDone, onNext, onCancel }: StepProps) {
  const t = useT();
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onDone(await post<SignedIn>('/api/v1/auth/totp', { ticket, code }));
    } catch (err) {
      if (!onNext(err)) setError(describeError(err));
      setCode('');
      setBusy(false);
    }
  };
  return (
    <>
      <div className="signin-title">
        <h1>{t('Two-step verification')}</h1>
        <p className="muted">{recovery ? t('Enter one of your recovery codes. Each code works once.') : t('Enter the 6-digit code from your authenticator app.')}</p>
      </div>
      <form className="signin-form" onSubmit={submit}>
        {error && (
          <div className="notice notice-error" role="alert">
            {error}
          </div>
        )}
        <Field label={recovery ? t('Recovery code') : t('Code from the app')}>
          <CodeInput key={String(recovery)} value={code} onChange={setCode} recovery={recovery} />
        </Field>
        <button className="btn btn-primary btn-block" type="submit" disabled={busy || code.trim().length < 6}>
          {busy ? <LoaderCircle size={16} className="spin" /> : <ShieldCheck size={16} />}
          {t('Verify')}
        </button>
        <button
          type="button"
          className="btn btn-ghost btn-block"
          onClick={() => {
            setRecovery(!recovery);
            setCode('');
            setError(null);
          }}
        >
          {recovery ? t('Use the authenticator app') : t('Use a recovery code')}
        </button>
        <button type="button" className="btn btn-ghost btn-block" onClick={onCancel}>
          {t('Back')}
        </button>
      </form>
    </>
  );
}

/** The policy requires a second factor and the person has none: set up the authenticator app before going on. */
function SetupStep({ ticket, username, onDone, onNext, onCancel }: StepProps & { username: string }) {
  const t = useT();
  return (
    <>
      <div className="signin-title">
        <h1>{t('Set up two-step verification')}</h1>
        <p className="muted">{t('The password policy requires a second factor for {user}. Set up an authenticator app to continue.', { user: username })}</p>
      </div>
      <div className="signin-form">
        <TotpSetupForm
          begin={() => post<TotpSetup>('/api/v1/auth/totp/setup', { ticket })}
          confirm={async (code) => {
            try {
              onDone(await post<SignedIn>('/api/v1/auth/totp/setup/confirm', { ticket, code }));
            } catch (err) {
              if (!onNext(err)) throw err;
            }
          }}
          onCancel={onCancel}
          submitLabel={t('Turn on and sign in')}
        />
      </div>
    </>
  );
}

/** The recovery codes of an authenticator app set up during the sign-in, before the sign-in goes on. */
function CodesStep({ codes, next, username }: { codes: string[]; next: string; username: string }) {
  const t = useT();
  return (
    <>
      <div className="signin-title">
        <h1>{t('Save your recovery codes')}</h1>
        <p className="muted">{t('Two-step verification is on.')}</p>
      </div>
      <div className="signin-form">
        <RecoveryCodes codes={codes} username={username} />
        <button type="button" className="btn btn-primary btn-block" onClick={() => go(next)}>
          {t('I have saved the codes, continue')}
        </button>
      </div>
    </>
  );
}
