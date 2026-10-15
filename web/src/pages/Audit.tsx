import { useEffect, useState } from 'react';
import { FileClock, Search } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';
import { get } from '../api/client';
import type { AuditEntry } from '../api/types';
import { Empty, ErrorNotice, Loading, PageHead } from '../components/ui';
import { formatDate, useT, type TFn } from '../i18n';

export function actionLabel(a: string, t: TFn): string {
  const m: Record<string, string> = {
    'auth.sign_in': t('Signed in'),
    'auth.sign_out': t('Signed out'),
    'auth.sign_in_failed': t('Sign-in failed'),
    'auth.password_changed': t('Changed the password'),
    'user.created': t('User created'),
    'user.updated': t('User changed'),
    'user.deleted': t('User deleted'),
    'user.password_reset': t('Password reset'),
    'user.unlocked': t('User unlocked'),
    'user.locked': t('User locked'),
    'user.linked': t('Account linked'),
    'user.passkeys_removed': t('Passkeys removed'),
    'user.signed_out': t('Signed out everywhere'),
    'passkey.added': t('Passkey added'),
    'passkey.removed': t('Passkey removed'),
    'group.saved': t('Group saved'),
    'group.deleted': t('Group deleted'),
    'application.connected': t('Application connected'),
    'application.updated': t('Application changed'),
    'application.key_issued': t('New connection key'),
    'application.removed': t('Application removed'),
    'application.roles_published': t('Roles published'),
    'oauth.token': t('Token issued'),
    'oauth.denied': t('Access denied'),
    'settings.password_policy': t('Password policy changed'),
    'settings.general': t('General settings changed'),
    'settings.ldap': t('Directory settings changed'),
    'settings.entra': t('Entra ID settings changed'),
    'settings.provider': t('Provider settings changed'),
    'settings.signing_key_rotated': t('Signing key rotated'),
  };
  return m[a] ?? a;
}

const tone = (a: string) => (a.endsWith('failed') || a.endsWith('denied') || a.endsWith('locked') ? 'pill-error' : a.startsWith('settings.') || a.startsWith('application.') ? 'pill-info' : a.startsWith('auth.') ? '' : 'pill-accent');

export function AuditPage() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get('q') ?? '');
  const [items, setItems] = useState<AuditEntry[] | null>(null);
  const [more, setMore] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const load = async (query: string, before?: number) => {
    try {
      const list = await get<AuditEntry[]>(`/api/v1/audit?q=${encodeURIComponent(query)}${before ? `&before=${before}` : ''}`);
      setItems((old) => (before && old ? [...old, ...list] : list));
      setMore(list.length === 100);
      setError(null);
    } catch (e) {
      setError(e);
    }
  };
  useEffect(() => {
    const h = setTimeout(() => {
      load(q);
      if (q) params.set('q', q);
      else params.delete('q');
      setParams(params, { replace: true });
    }, 250);
    return () => clearTimeout(h);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);
  return (
    <>
      <PageHead title={t('Audit log')} subtitle={t('Every sign-in and every change in SPA.')} />
      <div className="toolbar">
        <div className="search">
          <Search size={16} />
          <input className="input" placeholder={t('Search by person, action or object')} value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>
      <ErrorNotice error={error} />
      {!items ? (
        <Loading />
      ) : items.length === 0 ? (
        <div className="card">
          <Empty icon={<FileClock className="icon" />} title={t('Nothing found')} />
        </div>
      ) : (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('When')}</th>
                <th>{t('Who')}</th>
                <th>{t('What')}</th>
                <th>{t('Object')}</th>
                <th>{t('Details')}</th>
                <th>{t('Address')}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id}>
                  <td className="nowrap">{formatDate(e.at)}</td>
                  <td>{e.actor || '—'}</td>
                  <td>
                    <span className={`pill ${tone(e.action)}`} title={e.action}>
                      {actionLabel(e.action, t)}
                    </span>
                  </td>
                  <td>{e.target || '—'}</td>
                  <td>
                    <div className="audit-detail" title={e.detail ? JSON.stringify(e.detail) : ''}>
                      {e.detail && Object.keys(e.detail).length
                        ? Object.entries(e.detail)
                            .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
                            .join(' ')
                        : ''}
                    </div>
                  </td>
                  <td className="mono">{e.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {more && items && (
        <div className="row" style={{ justifyContent: 'center' }}>
          <button type="button" className="btn" onClick={() => load(q, items[items.length - 1].id)}>
            {t('Show older')}
          </button>
        </div>
      )}
    </>
  );
}
