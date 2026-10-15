import { useEffect, useState } from 'react';
import { AppWindow, Check, KeyRound, Link2, Plus, ShieldCheck, Trash2, X } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';
import { del, get, post, put } from '../api/client';
import type { AppInput, Application, ApplicationList, AppType, Assignment, Connection, Group, Role, User } from '../api/types';
import { ActionMenu, AppIcon, Confirm, Copy, Empty, ErrorNotice, Field, Loading, Modal, PageHead } from '../components/ui';
import { formatAgo, useT, type TFn } from '../i18n';
import { isAdmin, useAuth, useLoad } from '../lib/auth';
import { toast } from '../lib/toast';

const TYPES: AppType[] = ['umbrella-monitoring', 'umbrella-flow', 'inventory-db', 'network-control', 'oidc'];

export function typeLabel(type: AppType, t: TFn) {
  return type === 'oidc' ? t('OpenID Connect application') : { 'umbrella-monitoring': 'Umbrella Monitoring', 'umbrella-flow': 'Umbrella Flow', 'inventory-db': 'Inventory DB', 'network-control': 'Network Control' }[type];
}

function typeHint(type: AppType, t: TFn) {
  switch (type) {
    case 'umbrella-monitoring':
      return t('Incidents, on-call and the service catalogue');
    case 'umbrella-flow':
      return t('Workflows and automation');
    case 'inventory-db':
      return t('DCIM, IPAM and bases');
    case 'network-control':
      return t('Network devices and configuration');
    case 'oidc':
      return t('Any application that speaks OpenID Connect');
  }
}

const lines = (s: string) =>
  s
    .split('\n')
    .map((x) => x.trim())
    .filter(Boolean);

interface Directory {
  users: User[];
  groups: Group[];
}

/** Rules "person or group → role" of one application. */
function RulesEditor({ roles, rules, onChange, dir, defaultRole }: { roles: Role[]; rules: Assignment[]; onChange: (r: Assignment[]) => void; dir: Directory; defaultRole?: string }) {
  const t = useT();
  const set = (i: number, p: Partial<Assignment>) => onChange(rules.map((r, j) => (j === i ? { ...r, ...p } : r)));
  const first = defaultRole && roles.some((r) => r.id === defaultRole) ? defaultRole : (roles[roles.length - 1]?.id ?? '');
  return (
    <div className="stack" style={{ gap: 8 }}>
      {rules.length === 0 && <p className="muted">{t('No rules yet: nobody can sign in to the application.')}</p>}
      {rules.map((r, i) => {
        const subjects = r.subject_type === 'user' ? dir.users.map((u) => ({ id: u.id, name: `${u.name || u.username} (${u.username})` })) : dir.groups.map((g) => ({ id: g.id, name: g.name }));
        const known = roles.some((x) => x.id === r.role);
        return (
          <div className="rule-row" key={i}>
            <select className="input" value={r.subject_type} onChange={(e) => set(i, { subject_type: e.target.value as 'user' | 'group', subject_id: '' })}>
              <option value="group">{t('Group')}</option>
              <option value="user">{t('Person')}</option>
            </select>
            <select className="input" value={r.subject_id} onChange={(e) => set(i, { subject_id: e.target.value })}>
              <option value="">{t('Choose…')}</option>
              {subjects.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
            <select className="input" value={r.role} onChange={(e) => set(i, { role: e.target.value })}>
              {!known && <option value={r.role}>{t('{role} (unknown role)', { role: r.role })}</option>}
              {roles.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.name}
                </option>
              ))}
            </select>
            <button type="button" className="icon-btn" aria-label={t('Remove')} title={t('Remove')} onClick={() => onChange(rules.filter((_, j) => j !== i))}>
              <X size={16} />
            </button>
          </div>
        );
      })}
      <div>
        <button type="button" className="btn btn-sm" onClick={() => onChange([...rules, { subject_type: 'group', subject_id: '', role: first }])}>
          <Plus size={14} />
          {t('Add a rule')}
        </button>
      </div>
    </div>
  );
}

function RolesEditor({ roles, onChange }: { roles: Role[]; onChange: (r: Role[]) => void }) {
  const t = useT();
  return (
    <div className="stack" style={{ gap: 8 }}>
      {roles.map((r, i) => (
        <div className="rule-row" key={i} style={{ gridTemplateColumns: '160px minmax(0,1fr) 34px' }}>
          <input className="input mono" value={r.id} placeholder="viewer" onChange={(e) => onChange(roles.map((x, j) => (j === i ? { ...x, id: e.target.value } : x)))} />
          <input className="input" value={r.name} placeholder={t('Name')} onChange={(e) => onChange(roles.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)))} />
          <button type="button" className="icon-btn" aria-label={t('Remove')} onClick={() => onChange(roles.filter((_, j) => j !== i))}>
            <X size={16} />
          </button>
        </div>
      ))}
      <div>
        <button type="button" className="btn btn-sm" onClick={() => onChange([...roles, { id: '', name: '' }])}>
          <Plus size={14} />
          {t('Add a role')}
        </button>
      </div>
    </div>
  );
}

function KeyOnce({ conn }: { conn: Connection }) {
  const t = useT();
  return (
    <div className="stack" style={{ gap: 12 }}>
      <div className="notice notice-success">
        <b>{t('{name} is connected.', { name: conn.application.name })}</b> {t('Copy the connection key now: SPA shows it only once.')}
      </div>
      <div className="key-box">{conn.key}</div>
      <div className="row">
        <Copy value={conn.key} label={t('Copy the key')} />
      </div>
      <div className="auth-help">
        <strong>{t('In the application')}</strong>
        <ol>
          <li>
            {t('Put the key into the deployment configuration of the application:')} <code>SPA_CONNECTION_KEY=spa1.…</code> {t('(or a file named by SPA_CONNECTION_KEY_FILE, or the OpenBao key spa/connection_key).')}
          </li>
          <li>{t('Restart the application. Its sign-in page then offers "Sign in with SPA".')}</li>
          <li>
            {t('Redirect address registered in SPA:')} <code>{conn.application.callback}</code>
          </li>
        </ol>
      </div>
    </div>
  );
}

function Wizard({ list, dir, onClose, onDone }: { list: ApplicationList; dir: Directory; onClose: () => void; onDone: () => void }) {
  const t = useT();
  const [step, setStep] = useState(0);
  const [type, setType] = useState<AppType>('umbrella-monitoring');
  const [name, setName] = useState('');
  const [base, setBase] = useState('https://');
  const [redirects, setRedirects] = useState('');
  const [logouts, setLogouts] = useState('');
  const [roles, setRoles] = useState<Role[]>(list.presets['umbrella-monitoring']);
  const [rules, setRules] = useState<Assignment[]>([]);
  const [conn, setConn] = useState<Connection | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => setRoles(list.presets[type] ?? []), [type, list]);
  const baseOK = /^https?:\/\/[^/\s]+/.test(base);
  const canNext = baseOK && (type !== 'oidc' || lines(redirects).length > 0);
  const connect = async () => {
    setBusy(true);
    setError(null);
    try {
      const body: AppInput = {
        type,
        name,
        base_url: base,
        redirect_uris: type === 'oidc' ? lines(redirects) : undefined,
        logout_uris: type === 'oidc' ? lines(logouts) : undefined,
        roles: type === 'oidc' ? roles : undefined,
        assignments: rules.filter((r) => r.subject_id),
      };
      setConn(await post<Connection>('/api/v1/applications', body));
      setStep(2);
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const steps = [t('Application'), t('Access'), t('Connection key')];
  const callback = base.replace(/\/+$/, '') + '/api/auth/spa/callback';
  return (
    <Modal
      title={t('Connect an application')}
      onClose={onClose}
      width={720}
      footer={
        step === 2 ? (
          <button type="button" className="btn btn-primary" onClick={onClose}>
            {t('Done')}
          </button>
        ) : (
          <>
            {step > 0 && (
              <button type="button" className="btn" onClick={() => setStep(step - 1)}>
                {t('Back')}
              </button>
            )}
            <span className="spacer" />
            <button type="button" className="btn" onClick={onClose}>
              {t('Cancel')}
            </button>
            {step === 0 ? (
              <button type="button" className="btn btn-primary" disabled={!canNext} onClick={() => setStep(1)}>
                {t('Next')}
              </button>
            ) : (
              <button type="button" className="btn btn-primary" disabled={busy} onClick={connect}>
                <Link2 size={16} />
                {t('Connect')}
              </button>
            )}
          </>
        )
      }
    >
      <div className="wizard-steps">
        {steps.map((s, i) => (
          <div key={s} className={`wizard-step ${i === step ? 'active' : ''} ${i < step ? 'done' : ''}`}>
            <span className="num">{i < step ? <Check size={12} strokeWidth={3} /> : i + 1}</span>
            {s}
          </div>
        ))}
      </div>
      {step === 0 && (
        <>
          <div className="type-grid">
            {TYPES.map((x) => (
              <button key={x} type="button" className={`type-option ${type === x ? 'selected' : ''}`} onClick={() => setType(x)}>
                <AppIcon type={x} small />
                <span>{typeLabel(x, t)}</span>
                <span className="hint" style={{ fontWeight: 400 }}>
                  {typeHint(x, t)}
                </span>
              </button>
            ))}
          </div>
          <div className="grid-2">
            <Field label={t('Name')} hint={t('Shown to people on their home page')}>
              <input className="input" value={name} placeholder={typeLabel(type, t)} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label={t('Address')} hint={type === 'oidc' ? undefined : t('Redirect address: {url}', { url: callback })}>
              <input className="input" value={base} onChange={(e) => setBase(e.target.value)} placeholder="https://monitoring.example.com" />
            </Field>
          </div>
          {type === 'oidc' && (
            <div className="grid-2">
              <Field label={t('Redirect addresses')} hint={t('One per line, exactly as the application sends them')}>
                <textarea className="input mono" value={redirects} onChange={(e) => setRedirects(e.target.value)} placeholder="https://app.example.com/oauth/callback" />
              </Field>
              <Field label={t('Addresses after sign-out')} hint={t('One per line (optional)')}>
                <textarea className="input mono" value={logouts} onChange={(e) => setLogouts(e.target.value)} placeholder="https://app.example.com/" />
              </Field>
            </div>
          )}
        </>
      )}
      {step === 1 && (
        <>
          <section className="stack" style={{ gap: 8 }}>
            <h3>{t('Roles of the application')}</h3>
            {type === 'oidc' ? (
              <RolesEditor roles={roles} onChange={setRoles} />
            ) : (
              <>
                <div className="chips">
                  {roles.map((r) => (
                    <span key={r.id} className="pill pill-accent" title={r.description}>
                      {r.name} <span className="mono">{r.id}</span>
                    </span>
                  ))}
                </div>
                <p className="hint">{t('The application replaces this catalogue with its own roles once it connects.')}</p>
              </>
            )}
          </section>
          <section className="stack" style={{ gap: 8 }}>
            <h3>{t('Who gets which role')}</h3>
            <p className="hint">{t('People without a role in the application cannot sign in to it.')}</p>
            <RulesEditor roles={roles.filter((r) => r.id)} rules={rules} onChange={setRules} dir={dir} />
          </section>
        </>
      )}
      {step === 2 && conn && <KeyOnce conn={conn} />}
      <ErrorNotice error={error} />
    </Modal>
  );
}

function AccessDialog({ app, dir, onClose, onSaved }: { app: Application; dir: Directory; onClose: () => void; onSaved: () => void }) {
  const t = useT();
  const [name, setName] = useState(app.name);
  const [base, setBase] = useState(app.base_url);
  const [redirects, setRedirects] = useState((app.redirect_uris ?? []).join('\n'));
  const [roles, setRoles] = useState<Role[]>(app.roles);
  const [rules, setRules] = useState<Assignment[]>(app.assignments.map((a) => ({ subject_type: a.subject_type, subject_id: a.subject_id, role: a.role })));
  const [error, setError] = useState<unknown>(null);
  const editableRoles = !app.roles_published && app.type === 'oidc';
  const save = async () => {
    setError(null);
    try {
      await put(`/api/v1/applications/${app.id}`, {
        type: app.type,
        name,
        base_url: base,
        redirect_uris: app.type === 'oidc' ? lines(redirects) : undefined,
        logout_uris: app.logout_uris ?? [],
        roles: editableRoles ? roles : undefined,
        default_role: app.default_role,
        assignments: rules.filter((r) => r.subject_id),
      } satisfies AppInput);
      toast(t('Saved'));
      onSaved();
      onClose();
    } catch (e) {
      setError(e);
    }
  };
  return (
    <Modal
      title={
        <>
          <AppIcon type={app.type} small />
          {app.name}
        </>
      }
      onClose={onClose}
      width={720}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('Cancel')}
          </button>
          <button type="button" className="btn btn-primary" onClick={save}>
            {t('Save')}
          </button>
        </>
      }
    >
      <div className="grid-2">
        <Field label={t('Name')}>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label={t('Address')}>
          <input className="input" value={base} onChange={(e) => setBase(e.target.value)} />
        </Field>
      </div>
      {app.type === 'oidc' && (
        <Field label={t('Redirect addresses')}>
          <textarea className="input mono" value={redirects} onChange={(e) => setRedirects(e.target.value)} />
        </Field>
      )}
      <section className="stack" style={{ gap: 8 }}>
        <h3>{t('Roles of the application')}</h3>
        {editableRoles ? (
          <RolesEditor roles={roles} onChange={setRoles} />
        ) : (
          <>
            <div className="chips">
              {app.roles.map((r) => (
                <span key={r.id} className="pill pill-accent" title={r.description}>
                  {r.name} <span className="mono">{r.id}</span>
                </span>
              ))}
            </div>
            <p className="hint">{app.roles_published ? t('Published by the application {ago}.', { ago: formatAgo(app.roles_published) }) : t('The application replaces this catalogue with its own roles once it connects.')}</p>
          </>
        )}
      </section>
      <section className="stack" style={{ gap: 8 }}>
        <h3>{t('Who gets which role')}</h3>
        <RulesEditor roles={roles.filter((r) => r.id)} rules={rules} onChange={setRules} dir={dir} defaultRole={app.default_role} />
      </section>
      <ErrorNotice error={error} />
    </Modal>
  );
}

export function ApplicationsPage() {
  const t = useT();
  const { account } = useAuth();
  const admin = isAdmin(account);
  const [params, setParams] = useSearchParams();
  const { data, error, reload } = useLoad(() => Promise.all([get<ApplicationList>('/api/v1/applications'), get<User[]>('/api/v1/users'), get<Group[]>('/api/v1/groups')]));
  const [edit, setEdit] = useState<Application | null>(null);
  const [rekey, setRekey] = useState<Application | null>(null);
  const [remove, setRemove] = useState<Application | null>(null);
  const [newKey, setNewKey] = useState<Connection | null>(null);
  const wizard = params.get('connect') === '1' && admin;
  const closeWizard = () => {
    params.delete('connect');
    setParams(params, { replace: true });
  };
  const openWizard = () => {
    params.set('connect', '1');
    setParams(params);
  };
  const [list, users, groups] = data ?? [null, [], []];
  const dir = { users, groups };
  return (
    <>
      <PageHead
        title={t('Applications')}
        subtitle={t('Applications that sign people in with SPA, their roles and who gets them.')}
        actions={
          admin && (
            <button type="button" className="btn btn-primary" onClick={openWizard}>
              <Plus size={16} />
              {t('Connect an application')}
            </button>
          )
        }
      />
      <ErrorNotice error={error} />
      {!list ? (
        <Loading />
      ) : list.applications.length === 0 ? (
        <div className="card">
          <Empty
            icon={<AppWindow className="icon" />}
            title={t('No applications yet')}
            text={t('Connect Umbrella Monitoring, Umbrella Flow, Inventory DB, Network Control or any OpenID Connect application.')}
            action={
              admin && (
                <button type="button" className="btn btn-primary" onClick={openWizard}>
                  <Plus size={16} />
                  {t('Connect an application')}
                </button>
              )
            }
          />
        </div>
      ) : (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('Application')}</th>
                <th>{t('Roles')}</th>
                <th>{t('Rules')}</th>
                <th>{t('People')}</th>
                <th>{t('Last synchronisation')}</th>
                {admin && <th />}
              </tr>
            </thead>
            <tbody>
              {list.applications.map((a) => (
                <tr key={a.id}>
                  <td>
                    <div className="cell-main">
                      <AppIcon type={a.type} small />
                      <div>
                        <strong>{a.name}</strong>
                        <small>
                          {a.base_url.replace(/^https?:\/\//, '')} · <span className="mono">{a.client_id}</span>
                        </small>
                      </div>
                    </div>
                  </td>
                  <td>
                    <div className="chips">
                      {a.roles.slice(0, 4).map((r) => (
                        <span key={r.id} className="pill">
                          {r.name}
                        </span>
                      ))}
                      {a.roles.length > 4 && <span className="pill">+{a.roles.length - 4}</span>}
                    </div>
                  </td>
                  <td>
                    {a.assignments.length === 0 ? (
                      <span className="pill pill-warn">{t('no rules')}</span>
                    ) : (
                      <span className="hint" title={a.assignments.map((x) => `${x.subject_name} → ${x.role}`).join('\n')}>
                        {a.assignments
                          .slice(0, 2)
                          .map((x) => `${x.subject_name} → ${x.role}`)
                          .join(', ')}
                        {a.assignments.length > 2 ? ` +${a.assignments.length - 2}` : ''}
                      </span>
                    )}
                  </td>
                  <td>{a.users}</td>
                  <td className="nowrap">{a.last_sync_at ? formatAgo(a.last_sync_at) : <span className="pill">{t('not yet')}</span>}</td>
                  {admin && (
                    <td className="actions-cell">
                      <ActionMenu label={t('Actions')}>
                        {(close) => (
                          <>
                            <button type="button" className="um-item" onClick={() => (close(), setEdit(a))}>
                              <ShieldCheck size={16} />
                              {t('Access and settings')}
                            </button>
                            <button type="button" className="um-item" onClick={() => (close(), setRekey(a))}>
                              <KeyRound size={16} />
                              {t('Issue a new key')}
                            </button>
                            <div className="um-sep" />
                            <button type="button" className="um-item danger" onClick={() => (close(), setRemove(a))}>
                              <Trash2 size={16} />
                              {t('Remove')}
                            </button>
                          </>
                        )}
                      </ActionMenu>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {wizard && list && <Wizard list={list} dir={dir} onClose={closeWizard} onDone={reload} />}
      {edit && <AccessDialog app={edit} dir={dir} onClose={() => setEdit(null)} onSaved={reload} />}
      {rekey && (
        <Confirm
          title={t('Issue a new key for {name}?', { name: rekey.name })}
          text={t('The client secret and the federation token are replaced; the old key stops working at once. Put the new key into the application.')}
          confirm={t('Issue a new key')}
          danger
          onClose={() => setRekey(null)}
          onConfirm={async () => setNewKey(await post<Connection>(`/api/v1/applications/${rekey.id}/key`))}
        />
      )}
      {newKey && (
        <Modal
          title={t('New connection key')}
          onClose={() => setNewKey(null)}
          width={640}
          footer={
            <button type="button" className="btn btn-primary" onClick={() => setNewKey(null)}>
              {t('Done')}
            </button>
          }
        >
          <KeyOnce conn={newKey} />
        </Modal>
      )}
      {remove && (
        <Confirm
          title={t('Remove {name}?', { name: remove.name })}
          text={t('Nobody can sign in to the application with SPA any more; its rules are deleted.')}
          confirm={t('Remove')}
          danger
          onClose={() => setRemove(null)}
          onConfirm={async () => {
            await del(`/api/v1/applications/${remove.id}`);
            reload();
          }}
        />
      )}
    </>
  );
}
