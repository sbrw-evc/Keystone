import { useEffect, useState, type FormEvent } from 'react';
import { CheckCircle2, LoaderCircle } from 'lucide-react';
import { ApiError, CSRF } from '../api/client';
import { Brand, Copy, ErrorNotice, Field, Loading, PasswordInput, Preferences } from '../components/ui';
import { useT } from '../i18n';

/** The setup wizard of a new Keystone (backend internal/setup): the setup code, the storage, the first administrator,
 * the organisation and the public address, the trusted proxies. */

type Stage = 'storage' | 'admin' | 'organization' | 'proxies' | 'done';

interface PostgresIn {
  dsn?: string;
  host: string;
  port: number;
  database: string;
  user: string;
  password?: string;
  sslmode: string;
}

interface SetupStatus {
  stage: Stage;
  defaults?: { postgres: PostgresIn; openbao: { addr: string } };
  legacy?: { master_key: boolean; database?: boolean };
  public_url_hint?: string;
  proxy_hint?: string;
}

interface Answer {
  stage?: Stage;
  ok?: boolean;
  error?: string;
  initialized?: boolean;
  root_token_needed?: boolean;
  openbao_init?: { root_token: string; recovery_key: string };
}

const CODE_KEY = 'keystone.setup-code';

function storedCode(): string {
  try {
    return sessionStorage.getItem(CODE_KEY) ?? '';
  } catch {
    return '';
  }
}

async function call(code: string, path: string, body: unknown = {}): Promise<Answer> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Setup-Code': code, ...CSRF },
    body: JSON.stringify(body),
  });
  const data = (await res.json().catch(() => ({}))) as Answer & { code?: string; message?: string; violations?: string[]; extra?: Record<string, unknown> };
  if (!res.ok) throw new ApiError(res.status, data.code ?? 'error', data.message ?? res.statusText, data.violations ?? [], data.extra ?? {});
  return data;
}

function Busy({ busy }: { busy: boolean }) {
  return busy ? <LoaderCircle size={16} className="spin" /> : null;
}

export function SetupPage() {
  const t = useT();
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [code, setCode] = useState(storedCode);
  const [codeOK, setCodeOK] = useState(false);
  const [shown, setShown] = useState<Answer['openbao_init'] | null>(null);

  const load = () =>
    fetch('/api/setup')
      .then((r) => r.json())
      .then((s: SetupStatus) => setStatus(s))
      .catch(setLoadError);
  useEffect(() => {
    load();
  }, []);
  const next = (stage?: Stage) => {
    if (stage) setStatus((s) => (s ? { ...s, stage } : s));
  };
  const remember = (c: string) => {
    setCode(c);
    try {
      sessionStorage.setItem(CODE_KEY, c);
    } catch {
      /* private mode */
    }
  };

  let body;
  if (!status) body = loadError ? <ErrorNotice error={loadError} /> : <Loading />;
  else if (shown) body = <ShownOnce shown={shown} onDone={() => setShown(null)} />;
  else if (status.stage === 'done') body = <Done />;
  else if (!codeOK) body = <CodeStep code={code} onOK={(c) => (remember(c), setCodeOK(true))} />;
  else if (status.stage === 'storage')
    body = (
      <StorageStep
        code={code}
        status={status}
        onDone={(a) => {
          if (a.openbao_init) setShown(a.openbao_init);
          next(a.stage);
        }}
      />
    );
  else if (status.stage === 'admin') body = <AdminStep code={code} onDone={next} />;
  else if (status.stage === 'organization') body = <OrganizationStep code={code} hint={status.public_url_hint ?? location.origin} onDone={next} />;
  else body = <ProxiesStep code={code} hint={status.proxy_hint} onDone={next} />;

  const steps: [Stage, string][] = [
    ['storage', t('Storage')],
    ['admin', t('Administrator')],
    ['organization', t('Organization')],
    ['proxies', t('Proxies')],
  ];
  const at = status ? steps.findIndex(([s]) => s === status.stage) : -1;
  return (
    <div className="center-page">
      <div className="card signin-card" style={{ maxWidth: 620, width: '100%' }}>
        <div className="signin-top">
          <Brand />
          <Preferences />
        </div>
        <div className="signin-title">
          <h1>{t('Set up Keystone')}</h1>
          {status && status.stage !== 'done' && (
            <div className="wizard-steps" style={{ marginTop: 12 }}>
              {steps.map(([s, label], i) => (
                <div key={s} className={`wizard-step ${i === at ? 'active' : ''} ${at > i || status.stage === 'done' ? 'done' : ''}`}>
                  <span className="num">{i + 1}</span>
                  {label}
                </div>
              ))}
            </div>
          )}
        </div>
        {body}
      </div>
    </div>
  );
}

function CodeStep({ code: initial, onOK }: { code: string; onOK: (code: string) => void }) {
  const t = useT();
  const [code, setCode] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await call(code, '/api/setup/code');
      onOK(code);
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="signin-form" onSubmit={submit}>
      <p className="muted">{t('Keystone printed a one-time setup code to its log. Run the command below on the server and enter the code.')}</p>
      <pre className="key-box">docker compose logs keystone | grep setup_code</pre>
      <Field label={t('Setup code')}>
        <input className="input mono" value={code} onChange={(e) => setCode(e.target.value)} placeholder="XXXX-XXXX-XXXX" autoFocus autoComplete="off" />
      </Field>
      <ErrorNotice error={error} />
      <button type="submit" className="btn btn-primary btn-block" disabled={busy || !code.trim()}>
        <Busy busy={busy} />
        {t('Continue')}
      </button>
    </form>
  );
}

function Check({ result }: { result: Answer | null }) {
  const t = useT();
  if (!result) return null;
  return result.ok ? (
    <div className="notice notice-success">
      <b>{t('Connected')}</b>
      {result.initialized === false && ` ${t('OpenBao is not initialised yet: Keystone will initialise it.')}`}
      {result.root_token_needed && ` ${t('OpenBao is initialised already: enter its root token.')}`}
    </div>
  ) : (
    <div className="notice notice-error">
      <b>{t('No connection')}</b> {result.error}
    </div>
  );
}

function StorageStep({ code, status, onDone }: { code: string; status: SetupStatus; onDone: (a: Answer) => void }) {
  const t = useT();
  const [pg, setPg] = useState<PostgresIn>(status.defaults?.postgres ?? { host: 'postgres', port: 5432, database: 'spa', user: 'spa', sslmode: 'disable' });
  const [mode, setMode] = useState<'builtin' | 'external'>(status.defaults?.openbao.addr && status.defaults.openbao.addr !== 'http://openbao:8200' ? 'external' : 'builtin');
  const [bao, setBao] = useState({ addr: status.defaults?.openbao.addr ?? 'http://openbao:8200', mount: '', role_id: '', secret_id: '', root_token: '' });
  const [pgCheck, setPgCheck] = useState<Answer | null>(null);
  const [baoCheck, setBaoCheck] = useState<Answer | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState<unknown>(null);
  const openbao = { mode, ...bao };
  const run = async (what: string, f: () => Promise<void>) => {
    setBusy(what);
    setError(null);
    try {
      await f();
    } catch (x) {
      setError(x);
    } finally {
      setBusy('');
    }
  };
  const legacy = status.legacy;
  return (
    <form
      className="signin-form"
      onSubmit={(e) => {
        e.preventDefault();
        run('save', async () => onDone(await call(code, '/api/setup/storage', { postgres: pg, openbao })));
      }}
    >
      {legacy?.master_key && (
        <div className="notice notice-warning">
          <b>{t('An older installation.')}</b> {t('Its secrets are sealed with SPA_MASTER_KEY in the database. Connect OpenBao: Keystone moves them there and drops them from the database.')}
        </div>
      )}
      <h3>PostgreSQL</h3>
      <div className="grid-2">
        <Field label={t('Host')}>
          <input className="input mono" value={pg.host} onChange={(e) => setPg({ ...pg, host: e.target.value })} />
        </Field>
        <Field label={t('Port')}>
          <input className="input" type="number" value={pg.port} onChange={(e) => setPg({ ...pg, port: Number(e.target.value) })} />
        </Field>
        <Field label={t('Database')}>
          <input className="input mono" value={pg.database} onChange={(e) => setPg({ ...pg, database: e.target.value })} />
        </Field>
        <Field label={t('User')}>
          <input className="input mono" value={pg.user} onChange={(e) => setPg({ ...pg, user: e.target.value })} />
        </Field>
      </div>
      <Field label={t('Password')} hint={legacy?.database ? t('Empty — the password of the older installation') : t('POSTGRES_PASSWORD from .env (install.sh printed it)')}>
        <PasswordInput value={pg.password ?? ''} onChange={(v) => setPg({ ...pg, password: v })} autoComplete="off" />
      </Field>
      <Field label={t('SSL')}>
        <select className="input" value={pg.sslmode} onChange={(e) => setPg({ ...pg, sslmode: e.target.value })}>
          <option value="disable">disable</option>
          <option value="require">require</option>
          <option value="verify-full">verify-full</option>
        </select>
      </Field>
      <button type="button" className="btn" disabled={!!busy} onClick={() => run('pg', async () => setPgCheck(await call(code, '/api/setup/postgres/test', { postgres: pg })))}>
        <Busy busy={busy === 'pg'} />
        {t('Check')}
      </button>
      <Check result={pgCheck} />

      <h3>OpenBao</h3>
      <div className="segmented">
        <button type="button" className={mode === 'builtin' ? 'active' : ''} onClick={() => setMode('builtin')}>
          {t('Built-in: initialise it')}
        </button>
        <button type="button" className={mode === 'external' ? 'active' : ''} onClick={() => setMode('external')}>
          {t('External: an AppRole')}
        </button>
      </div>
      <p className="hint">
        {mode === 'builtin'
          ? t('The OpenBao of the compose file. Keystone initialises it, turns on KV v2 and an AppRole for itself, and shows the root token and the recovery key once.')
          : t('An OpenBao of yours with a KV v2 mount and an AppRole whose policy lets Keystone read and write that mount.')}
      </p>
      <Field label={t('Address')}>
        <input className="input mono" value={bao.addr} onChange={(e) => setBao({ ...bao, addr: e.target.value })} />
      </Field>
      {mode === 'external' ? (
        <>
          <Field label={t('KV v2 mount')}>
            <input className="input mono" value={bao.mount} placeholder="keystone" onChange={(e) => setBao({ ...bao, mount: e.target.value })} />
          </Field>
          <Field label="role_id">
            <input className="input mono" value={bao.role_id} onChange={(e) => setBao({ ...bao, role_id: e.target.value })} />
          </Field>
          <Field label="secret_id">
            <PasswordInput value={bao.secret_id} onChange={(v) => setBao({ ...bao, secret_id: v })} autoComplete="off" />
          </Field>
        </>
      ) : (
        baoCheck?.root_token_needed && (
          <Field label={t('Root token')}>
            <PasswordInput value={bao.root_token} onChange={(v) => setBao({ ...bao, root_token: v })} autoComplete="off" />
          </Field>
        )
      )}
      <button type="button" className="btn" disabled={!!busy} onClick={() => run('bao', async () => setBaoCheck(await call(code, '/api/setup/openbao/test', { openbao })))}>
        <Busy busy={busy === 'bao'} />
        {t('Check')}
      </button>
      <Check result={baoCheck} />
      <ErrorNotice error={error} />
      <button type="submit" className="btn btn-primary btn-block" disabled={!!busy}>
        <Busy busy={busy === 'save'} />
        {t('Save and continue')}
      </button>
    </form>
  );
}

function ShownOnce({ shown, onDone }: { shown: NonNullable<Answer['openbao_init']>; onDone: () => void }) {
  const t = useT();
  const [saved, setSaved] = useState(false);
  return (
    <div className="signin-form">
      <div className="notice notice-warning">
        <b>{t('Save these now.')}</b> {t('Keystone does not keep the root token and the recovery key of OpenBao and shows them only once. Keep them in a safe place, apart from the server.')}
      </div>
      <Field label={t('Root token')}>
        <div className="key-box">{shown.root_token}</div>
      </Field>
      <Copy value={shown.root_token} label={t('Copy the root token')} />
      <Field label={t('Recovery key')}>
        <div className="key-box">{shown.recovery_key}</div>
      </Field>
      <Copy value={shown.recovery_key} label={t('Copy the recovery key')} />
      <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} /> {t('I saved them')}
      </label>
      <button type="button" className="btn btn-primary btn-block" disabled={!saved} onClick={onDone}>
        {t('Continue')}
      </button>
    </div>
  );
}

function useStep<T>(code: string, path: string, onDone: (s?: Stage) => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const submit = async (body: T) => {
    setBusy(true);
    setError(null);
    try {
      onDone((await call(code, path, body)).stage);
    } catch (x) {
      setError(x);
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, submit };
}

function AdminStep({ code, onDone }: { code: string; onDone: (s?: Stage) => void }) {
  const t = useT();
  const [v, setV] = useState({ username: 'admin', name: '', email: '', password: '' });
  const [again, setAgain] = useState('');
  const { busy, error, submit } = useStep<typeof v>(code, '/api/setup/admin', onDone);
  return (
    <form
      className="signin-form"
      onSubmit={(e) => {
        e.preventDefault();
        submit(v);
      }}
    >
      <p className="muted">{t('The first administrator of Keystone: a local account with a password.')}</p>
      <Field label={t('User name')}>
        <input className="input" value={v.username} onChange={(e) => setV({ ...v, username: e.target.value })} autoFocus />
      </Field>
      <Field label={t('Name')}>
        <input className="input" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} />
      </Field>
      <Field label={t('E-mail')}>
        <input className="input" type="email" value={v.email} onChange={(e) => setV({ ...v, email: e.target.value })} />
      </Field>
      <Field label={t('Password')}>
        <PasswordInput value={v.password} onChange={(x) => setV({ ...v, password: x })} autoComplete="new-password" />
      </Field>
      <Field label={t('Repeat the password')}>
        <PasswordInput value={again} onChange={setAgain} autoComplete="new-password" />
      </Field>
      <ErrorNotice error={error} />
      <button type="submit" className="btn btn-primary btn-block" disabled={busy || !v.username || !v.password || v.password !== again}>
        <Busy busy={busy} />
        {t('Create the administrator')}
      </button>
    </form>
  );
}

function OrganizationStep({ code, hint, onDone }: { code: string; hint: string; onDone: (s?: Stage) => void }) {
  const t = useT();
  const [v, setV] = useState({ organization: '', public_url: hint });
  const { busy, error, submit } = useStep<typeof v>(code, '/api/setup/organization', onDone);
  return (
    <form
      className="signin-form"
      onSubmit={(e) => {
        e.preventDefault();
        submit(v);
      }}
    >
      <Field label={t('Organization')} hint={t('Shown on the sign-in page')}>
        <input className="input" value={v.organization} onChange={(e) => setV({ ...v, organization: e.target.value })} autoFocus />
      </Field>
      <Field label={t('Public address')} hint={t('The address of Keystone and its OpenID Connect issuer, exactly as browsers and applications reach it. Changing it later makes connected applications reject Keystone until they get a new key.')}>
        <input className="input mono" value={v.public_url} onChange={(e) => setV({ ...v, public_url: e.target.value })} placeholder="https://keystone.example.com" />
      </Field>
      <ErrorNotice error={error} />
      <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
        <Busy busy={busy} />
        {t('Continue')}
      </button>
    </form>
  );
}

function ProxiesStep({ code, hint, onDone }: { code: string; hint?: string; onDone: (s?: Stage) => void }) {
  const t = useT();
  const [text, setText] = useState(hint ?? '');
  const { busy, error, submit } = useStep<{ trusted_proxies: string[] }>(code, '/api/setup/proxies', onDone);
  return (
    <form
      className="signin-form"
      onSubmit={(e) => {
        e.preventDefault();
        submit({ trusted_proxies: text.split(/[\s,]+/).filter(Boolean) });
      }}
    >
      <p className="muted">{t('Addresses or networks of reverse proxies whose X-Forwarded-For and X-Forwarded-Host are believed, one per line.')}</p>
      {hint && <div className="notice">{t('This request came through a proxy at {address}.', { address: hint })}</div>}
      <Field label={t('Trusted proxies')} hint={t('Empty when browsers reach Keystone directly.')}>
        <textarea className="input mono" rows={3} value={text} onChange={(e) => setText(e.target.value)} placeholder="192.168.0.100" />
      </Field>
      <ErrorNotice error={error} />
      <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
        <Busy busy={busy} />
        {t('Finish')}
      </button>
    </form>
  );
}

function Done() {
  const t = useT();
  useEffect(() => {
    try {
      sessionStorage.removeItem(CODE_KEY);
    } catch {
      /* private mode */
    }
  }, []);
  return (
    <div className="signin-form" style={{ textAlign: 'center' }}>
      <CheckCircle2 size={40} style={{ color: "var(--ok)" }} />
      <p>{t('Keystone is set up. Sign in as the administrator and go through the first steps.')}</p>
      <a className="btn btn-primary btn-block" href="/signin">
        {t('Sign in')}
      </a>
    </div>
  );
}
