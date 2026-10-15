import { useEffect, useState } from 'react';
import { LoaderCircle } from 'lucide-react';
import { get, put } from '../api/client';
import type { PasswordPolicy, PolicySummary } from '../api/types';
import { ErrorNotice, Field, Loading, PageHead, Switch } from '../components/ui';
import { useT } from '../i18n';
import { isAdmin, useAuth, useLoad } from '../lib/auth';
import { toast } from '../lib/toast';
import { PolicyRules } from './SignIn';

function Num({ value, onChange, min, max, disabled, suffix }: { value: number; onChange: (n: number) => void; min: number; max: number; disabled?: boolean; suffix?: string }) {
  return (
    <div className="input-affix numeric">
      <input className="input" type="number" min={min} max={max} value={value} disabled={disabled} onChange={(e) => onChange(Number(e.target.value))} />
      {suffix && <span className="affix">{suffix}</span>}
    </div>
  );
}

export function PasswordPolicyPage() {
  const t = useT();
  const { account } = useAuth();
  const admin = isAdmin(account);
  const { data, error, setData } = useLoad(() => get<PolicySummary>('/api/v1/settings/password-policy'));
  const [p, setP] = useState<PasswordPolicy | null>(null);
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<unknown>(null);
  const [sample, setSample] = useState('');
  useEffect(() => {
    if (data) setP(data.policy);
  }, [data]);
  if (!data || !p) return error ? <ErrorNotice error={error} /> : <Loading />;
  const set = (x: Partial<PasswordPolicy>) => setP({ ...p, ...x });
  const save = async () => {
    setBusy(true);
    setSaveError(null);
    try {
      setData(await put<PolicySummary>('/api/v1/settings/password-policy', p));
      toast(t('The password policy is saved'));
    } catch (e) {
      setSaveError(e);
    } finally {
      setBusy(false);
    }
  };
  const ro = !admin;
  return (
    <>
      <PageHead
        title={t('Password policy')}
        subtitle={t('Rules for the passwords of local accounts. Directory accounts follow the policy of their directory.')}
        actions={
          admin && (
            <button type="button" className="btn btn-primary" onClick={save} disabled={busy}>
              {busy && <LoaderCircle size={16} className="spin" />}
              {t('Save')}
            </button>
          )
        }
      />
      <div className="counters">
        <div className="counter">
          <span className="counter-num">{data.local_users}</span>
          <span className="counter-label">{t('Local accounts')}</span>
        </div>
        <div className={`counter ${data.expiring_users ? 'warn' : ''}`}>
          <span className="counter-num">{data.expiring_users}</span>
          <span className="counter-label">{t('Expire soon')}</span>
        </div>
        <div className={`counter ${data.expired_users ? 'warn' : ''}`}>
          <span className="counter-num">{data.expired_users}</span>
          <span className="counter-label">{t('Expired')}</span>
        </div>
        <div className="counter">
          <span className="counter-num">{data.locked_users}</span>
          <span className="counter-label">{t('Locked now')}</span>
        </div>
      </div>
      <ErrorNotice error={saveError} />
      <section className="card">
        <div className="card-head">
          <h2>{t('Complexity')}</h2>
        </div>
        <div className="card-body">
          <div className="grid-3">
            <Field label={t('Minimum length')}>
              <Num value={p.min_length} min={8} max={128} disabled={ro} onChange={(n) => set({ min_length: n })} suffix={t('characters')} />
            </Field>
            <Field label={t('Allowed letters')}>
              <select className="input" value={p.letters} disabled={ro} onChange={(e) => set({ letters: e.target.value as PasswordPolicy['letters'] })}>
                <option value="latin">{t('Latin')}</option>
                <option value="cyrillic">{t('Cyrillic')}</option>
                <option value="latin_cyrillic">{t('Latin and Cyrillic')}</option>
                <option value="any">{t('Any')}</option>
              </select>
            </Field>
          </div>
          <div className="grid-3">
            <div className="stack" style={{ gap: 8 }}>
              <Switch checked={p.require_digits} disabled={ro} onChange={(v) => set({ require_digits: v, min_digits: v ? Math.max(1, p.min_digits) : 0 })} label={t('Digits')} />
              {p.require_digits && <Num value={p.min_digits} min={1} max={16} disabled={ro} onChange={(n) => set({ min_digits: n })} suffix={t('at least')} />}
            </div>
            <div className="stack" style={{ gap: 8 }}>
              <Switch checked={p.require_special} disabled={ro} onChange={(v) => set({ require_special: v, min_special: v ? Math.max(1, p.min_special) : 0 })} label={t('Special characters')} />
              {p.require_special && <Num value={p.min_special} min={1} max={16} disabled={ro} onChange={(n) => set({ min_special: n })} suffix={t('at least')} />}
            </div>
            <Switch checked={p.require_mixed_case} disabled={ro} onChange={(v) => set({ require_mixed_case: v })} label={t('Upper- and lower-case letters')} />
          </div>
          <Switch checked={p.block_common} disabled={ro} onChange={(v) => set({ block_common: v })} label={t('Block common passwords')} hint={t('The most common passwords, keyboard sequences and the user name with a few characters added')} />
        </div>
      </section>
      <section className="card">
        <div className="card-head">
          <h2>{t('Lifetime and history')}</h2>
        </div>
        <div className="card-body grid-3">
          <Field label={t('Password lifetime')} hint={t('0 — passwords do not expire')}>
            <Num value={p.max_age_days} min={0} max={3650} disabled={ro} onChange={(n) => set({ max_age_days: n })} suffix={t('days')} />
          </Field>
          <Field label={t('Warn before expiry')}>
            <Num value={p.warn_days} min={0} max={90} disabled={ro || p.max_age_days === 0} onChange={(n) => set({ warn_days: n })} suffix={t('days')} />
          </Field>
          <Field label={t('Password history')} hint={t('A new password must differ from this many previous ones')}>
            <Num value={p.history_count} min={0} max={24} disabled={ro} onChange={(n) => set({ history_count: n })} suffix={t('passwords')} />
          </Field>
        </div>
      </section>
      <section className="card">
        <div className="card-head">
          <h2>{t('Lockout')}</h2>
        </div>
        <div className="card-body grid-3">
          <Field label={t('Lock after wrong passwords')} hint={t('0 — only the built-in limits (20 in a row)')}>
            <Num value={p.lockout_attempts} min={0} max={100} disabled={ro} onChange={(n) => set({ lockout_attempts: n })} suffix={t('attempts')} />
          </Field>
          <Field label={t('Lock for')}>
            <Num value={p.lockout_minutes} min={1} max={1440} disabled={ro || p.lockout_attempts === 0} onChange={(n) => set({ lockout_minutes: n })} suffix={t('minutes')} />
          </Field>
        </div>
      </section>
      <section className="card">
        <div className="card-head">
          <h2>{t('Try a password')}</h2>
        </div>
        <div className="card-body grid-2" style={{ alignItems: 'start' }}>
          <input className="input" value={sample} onChange={(e) => setSample(e.target.value)} placeholder={t('Type a password to check it against the rules')} />
          <PolicyRules policy={p} password={sample} />
        </div>
      </section>
    </>
  );
}
