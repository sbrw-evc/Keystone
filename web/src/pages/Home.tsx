import { ArrowUpRight, Check, CircleAlert, LayoutGrid } from 'lucide-react';
import { Link } from 'react-router-dom';
import { get } from '../api/client';
import type { Onboarding, Step } from '../api/types';
import { AppIcon, Empty, PageHead } from '../components/ui';
import { formatDate, useT, type TFn } from '../i18n';
import { canAudit, useAuth, useLoad } from '../lib/auth';

export function stepText(id: Step['id'], t: TFn): { title: string; text: string } {
  switch (id) {
    case 'public_url':
      return { title: t('Set the public address of Keystone'), text: t('SPA_PUBLIC_URL is the issuer that applications trust; set it in the deployment.') };
    case 'policy':
      return { title: t('Tighten the password policy'), text: t('Block common passwords, keep a password history and lock accounts after wrong passwords.') };
    case 'passkey':
      return { title: t('Add a passkey to your account'), text: t('Sign in with Windows Hello, Touch ID or a security key instead of a password.') };
    case 'directory':
      return { title: t('Connect a directory or a provider'), text: t('Active Directory, LDAP, Microsoft Entra ID, Google, Apple or any OpenID Connect provider.') };
    case 'application':
      return { title: t('Connect the first application'), text: t('Beacon, Current, Ledger, Network Control or any OpenID Connect application.') };
    case 'roles':
      return { title: t('Give people roles in the applications'), text: t('People without a role in an application cannot sign in to it.') };
    case 'second_admin':
      return { title: t('Add a second administrator'), text: t('So that Keystone stays manageable when one administrator is away.') };
  }
}

function FirstSteps() {
  const t = useT();
  const { data } = useLoad(() => get<Onboarding>('/api/v1/onboarding'));
  if (!data || data.done) return null;
  const done = data.steps.filter((s) => s.done).length;
  return (
    <section className="card">
      <div className="card-head" style={{ paddingBottom: 12 }}>
        <div>
          <h2>{t('First steps')}</h2>
          <p className="muted">{t('{done} of {total} done', { done, total: data.steps.length })}</p>
        </div>
        <div className="progress" style={{ width: 180 }}>
          <span style={{ width: `${(done / data.steps.length) * 100}%` }} />
        </div>
      </div>
      <div className="steps">
        {data.steps.map((s, i) => {
          const txt = stepText(s.id, t);
          return (
            <Link key={s.id} to={s.path} className={`step ${s.done ? 'done' : ''}`}>
              <span className="step-mark">{s.done ? <Check size={14} strokeWidth={3} /> : i + 1}</span>
              <div>
                <span className="step-title">
                  {txt.title} {s.optional && <span className="pill">{t('optional')}</span>}
                </span>
                <span className="hint">{txt.text}</span>
              </div>
              <ArrowUpRight size={16} className="muted" />
            </Link>
          );
        })}
      </div>
    </section>
  );
}

export function HomePage() {
  const t = useT();
  const { account } = useAuth();
  if (!account) return null;
  const first = (account.name || account.username).split(' ')[0];
  return (
    <>
      <PageHead title={t('Hello, {name}', { name: first })} subtitle={t('Your applications. Sign in once, open any of them.')} />
      {account.password_expires_soon && account.password_expires_at && (
        <div className="notice notice-warning row">
          <CircleAlert size={18} />
          <span>
            <b>{t('Your password expires on {date}.', { date: formatDate(account.password_expires_at, false) })}</b> <Link to="/profile">{t('Change it now')}</Link>
          </span>
        </div>
      )}
      {account.applications.length ? (
        <div className="app-tiles">
          {account.applications.map((a) => (
            <a key={a.id} className="app-tile" href={a.url}>
              <div className="app-tile-top">
                <AppIcon type={a.type} />
                <div>
                  <strong>{a.name}</strong>
                  <small>{a.url.replace(/^https?:\/\//, '')}</small>
                </div>
                <ArrowUpRight size={18} className="app-tile-open" />
              </div>
              <div className="chips">
                {a.roles.map((r) => (
                  <span key={r} className="pill pill-accent">
                    {r}
                  </span>
                ))}
              </div>
            </a>
          ))}
        </div>
      ) : (
        <div className="card">
          <Empty icon={<LayoutGrid className="icon" />} title={t('No applications yet')} text={t('An administrator gives you roles in the applications; they appear here.')} />
        </div>
      )}
      {canAudit(account) && <FirstSteps />}
    </>
  );
}
