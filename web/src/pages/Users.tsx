import { useMemo, useState } from 'react';
import { KeyRound, Lock, LockOpen, LogOut, Pencil, Plus, Search, ShieldOff, Trash2, UserPlus, Users } from 'lucide-react';
import { del, get, post, put } from '../api/client';
import type { Group, SPARole, User, UserInput } from '../api/types';
import { ActionMenu, Avatar, Confirm, Empty, ErrorNotice, Field, Loading, Modal, PageHead, PasswordInput, Switch } from '../components/ui';
import { formatAgo, useT } from '../i18n';
import { isAdmin, useAuth, useLoad } from '../lib/auth';
import { toast, toastError } from '../lib/toast';
import { sourceLabel } from './Profile';

export function useRoleLabels() {
  const t = useT();
  return { admin: t('Administrator'), auditor: t('Auditor'), user: t('User') } as Record<SPARole, string>;
}

function UserDialog({ user, groups, onClose, onSaved }: { user: User | null; groups: Group[]; onClose: () => void; onSaved: () => void }) {
  const t = useT();
  const roles = useRoleLabels();
  const [v, setV] = useState<UserInput>(
    user
      ? { username: user.username, name: user.name, email: user.email, spa_role: user.spa_role, disabled: user.disabled, groups: user.groups }
      : { username: '', name: '', email: '', spa_role: 'user', disabled: false, password: '', groups: [] },
  );
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const local = groups.filter((g) => g.source === 'local');
  const set = (p: Partial<UserInput>) => setV((x) => ({ ...x, ...p }));
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      // Only local groups are set here; directory groups follow the directory.
      const body = { ...v, groups: (v.groups ?? []).filter((id) => local.some((g) => g.id === id)) };
      if (user) await put(`/api/v1/users/${user.id}`, body);
      else await post('/api/v1/users', body);
      toast(user ? t('Saved') : t('The user is created. They choose a new password at the first sign-in'));
      onSaved();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Modal
      title={user ? t('Edit {name}', { name: user.name || user.username }) : t('New user')}
      onClose={onClose}
      width={560}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('Cancel')}
          </button>
          <button type="button" className="btn btn-primary" onClick={save} disabled={busy || !v.username || (!user && !v.password)}>
            {user ? t('Save') : t('Create')}
          </button>
        </>
      }
    >
      <div className="grid-2">
        <Field label={t('User name')}>
          <input className="input" value={v.username} disabled={!!user && user.source !== 'local'} onChange={(e) => set({ username: e.target.value })} autoFocus={!user} />
        </Field>
        <Field label={t('SPA role')} hint={t('Administrators manage SPA, auditors read everything')}>
          <select className="input" value={v.spa_role} onChange={(e) => set({ spa_role: e.target.value as SPARole })}>
            {(['user', 'auditor', 'admin'] as SPARole[]).map((r) => (
              <option key={r} value={r}>
                {roles[r]}
              </option>
            ))}
          </select>
        </Field>
        <Field label={t('Full name')}>
          <input className="input" value={v.name} onChange={(e) => set({ name: e.target.value })} />
        </Field>
        <Field label={t('E-mail')}>
          <input className="input" type="email" value={v.email} onChange={(e) => set({ email: e.target.value })} />
        </Field>
      </div>
      {!user && (
        <Field label={t('Initial password')} hint={t('The person changes it at the first sign-in')}>
          <PasswordInput value={v.password ?? ''} onChange={(p) => set({ password: p })} autoComplete="new-password" />
        </Field>
      )}
      {local.length > 0 && (
        <Field label={t('Groups')}>
          <div className="chips">
            {local.map((g) => {
              const on = v.groups?.includes(g.id);
              return (
                <button
                  key={g.id}
                  type="button"
                  className={`pill ${on ? 'pill-accent' : ''}`}
                  style={{ border: 0, cursor: 'pointer' }}
                  onClick={() => set({ groups: on ? v.groups!.filter((x) => x !== g.id) : [...(v.groups ?? []), g.id] })}
                >
                  {g.name}
                </button>
              );
            })}
          </div>
        </Field>
      )}
      {user && <Switch checked={v.disabled} onChange={(d) => set({ disabled: d })} label={t('Disabled')} hint={t('A disabled person cannot sign in; their sessions in SPA and the applications end')} />}
      <ErrorNotice error={error} />
    </Modal>
  );
}

function ResetPassword({ user, onClose }: { user: User; onClose: () => void }) {
  const t = useT();
  const [pw, setPw] = useState('');
  const [error, setError] = useState<unknown>(null);
  return (
    <Modal
      title={t('Reset the password of {name}', { name: user.name || user.username })}
      onClose={onClose}
      width={460}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('Cancel')}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!pw}
            onClick={async () => {
              try {
                await post(`/api/v1/users/${user.id}/password`, { password: pw });
                toast(t('The password is reset; the person changes it at the next sign-in'));
                onClose();
              } catch (e) {
                setError(e);
              }
            }}
          >
            {t('Reset password')}
          </button>
        </>
      }
    >
      <Field label={t('Temporary password')} hint={t('Their sessions end; they choose a new password at the next sign-in')}>
        <PasswordInput value={pw} onChange={setPw} autoComplete="new-password" autoFocus />
      </Field>
      <ErrorNotice error={error} />
    </Modal>
  );
}

function RowMenu({ user, me, onEdit, onReset, onChanged, onDelete }: { user: User; me: string; onEdit: () => void; onReset: () => void; onChanged: () => void; onDelete: () => void }) {
  const t = useT();
  const act = async (fn: () => Promise<unknown>, msg: string) => {
    try {
      await fn();
      toast(msg);
      onChanged();
    } catch (e) {
      toastError(e);
    }
  };
  return (
    <ActionMenu label={t('Actions')}>
      {(close) => (
        <>
          <button type="button" className="um-item" onClick={() => (close(), onEdit())}>
            <Pencil size={16} />
            {t('Edit')}
          </button>
          {user.source === 'local' && (
            <button type="button" className="um-item" onClick={() => (close(), onReset())}>
              <KeyRound size={16} />
              {t('Reset password')}
            </button>
          )}
          {user.locked && (
            <button type="button" className="um-item" onClick={() => (close(), act(() => post(`/api/v1/users/${user.id}/unlock`), t('Unlocked')))}>
              <LockOpen size={16} />
              {t('Unlock')}
            </button>
          )}
          <button type="button" className="um-item" onClick={() => (close(), act(() => del(`/api/v1/users/${user.id}/sessions`), t('Signed out everywhere')))}>
            <LogOut size={16} />
            {t('Sign out everywhere')}
          </button>
          {user.passkeys > 0 && (
            <button type="button" className="um-item" onClick={() => (close(), act(() => del(`/api/v1/users/${user.id}/passkeys`), t('Passkeys removed')))}>
              <Lock size={16} />
              {t('Remove all passkeys')}
            </button>
          )}
          {user.totp && (
            <button type="button" className="um-item" onClick={() => (close(), act(() => del(`/api/v1/users/${user.id}/totp`), t('Two-step verification is off')))}>
              <ShieldOff size={16} />
              {t('Turn off two-step verification')}
            </button>
          )}
          {user.id !== me && (
            <>
              <div className="um-sep" />
              <button type="button" className="um-item danger" onClick={() => (close(), onDelete())}>
                <Trash2 size={16} />
                {t('Delete')}
              </button>
            </>
          )}
        </>
      )}
    </ActionMenu>
  );
}

export function UsersPage() {
  const t = useT();
  const roles = useRoleLabels();
  const { account } = useAuth();
  const admin = isAdmin(account);
  const { data, error, reload } = useLoad(() => Promise.all([get<User[]>('/api/v1/users'), get<Group[]>('/api/v1/groups')]));
  const [q, setQ] = useState('');
  const [edit, setEdit] = useState<User | 'new' | null>(null);
  const [reset, setReset] = useState<User | null>(null);
  const [remove, setRemove] = useState<User | null>(null);
  const [users, groups] = data ?? [[], []];
  const groupName = useMemo(() => Object.fromEntries(groups.map((g) => [g.id, g.name])), [groups]);
  const list = users.filter((u) => !q || `${u.username} ${u.name} ${u.email}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <PageHead
        title={t('Users')}
        subtitle={t('Everyone who signs in through SPA: local accounts and people from directories and providers.')}
        actions={
          admin && (
            <button type="button" className="btn btn-primary" onClick={() => setEdit('new')}>
              <UserPlus size={16} />
              {t('New user')}
            </button>
          )
        }
      />
      <div className="toolbar">
        <div className="search">
          <Search size={16} />
          <input className="input" placeholder={t('Search by name, user name or e-mail')} value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <span className="muted">{t('Found: {n}', { n: list.length })}</span>
      </div>
      <ErrorNotice error={error} />
      {!data ? (
        <Loading />
      ) : list.length === 0 ? (
        <div className="card">
          <Empty icon={<Users className="icon" />} title={t('Nobody found')} action={admin && <button className="btn btn-primary" onClick={() => setEdit('new')}><Plus size={16} />{t('New user')}</button>} />
        </div>
      ) : (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('Person')}</th>
                <th>{t('Signs in with')}</th>
                <th>{t('SPA role')}</th>
                <th>{t('Groups')}</th>
                <th>{t('Applications')}</th>
                <th>{t('Last sign-in')}</th>
                {admin && <th />}
              </tr>
            </thead>
            <tbody>
              {list.map((u) => (
                <tr key={u.id}>
                  <td>
                    <div className="cell-main">
                      <Avatar name={u.name || u.username} />
                      <div>
                        <strong>
                          {u.name || u.username} {u.disabled && <span className="pill pill-error">{t('disabled')}</span>} {u.locked && <span className="pill pill-warn">{t('locked')}</span>}
                        </strong>
                        <small>
                          {u.username}
                          {u.email ? ` · ${u.email}` : ''}
                        </small>
                      </div>
                    </div>
                  </td>
                  <td>
                    <span className="nowrap">{sourceLabel(u.source, t)}</span>
                    {u.passkeys > 0 && <div className="hint">{t('Passkeys: {n}', { n: u.passkeys })}</div>}
                    {u.totp && <div className="hint">{t('Two-step verification')}</div>}
                  </td>
                  <td>
                    <span className={`pill ${u.spa_role === 'admin' ? 'pill-accent' : u.spa_role === 'auditor' ? 'pill-info' : ''}`}>{roles[u.spa_role]}</span>
                  </td>
                  <td>
                    <div className="chips">
                      {u.groups.map((g) => (
                        <span key={g} className="pill">
                          {groupName[g] ?? g}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>{Object.keys(u.app_roles ?? {}).length || '—'}</td>
                  <td className="nowrap">{u.last_sign_in_at ? formatAgo(u.last_sign_in_at) : t('never')}</td>
                  {admin && (
                    <td className="actions-cell">
                      <RowMenu user={u} me={account!.id} onEdit={() => setEdit(u)} onReset={() => setReset(u)} onChanged={reload} onDelete={() => setRemove(u)} />
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {edit && <UserDialog user={edit === 'new' ? null : edit} groups={groups} onClose={() => setEdit(null)} onSaved={reload} />}
      {reset && <ResetPassword user={reset} onClose={() => setReset(null)} />}
      {remove && (
        <Confirm
          title={t('Delete {name}?', { name: remove.name || remove.username })}
          text={t('The account, its passkeys, sessions and roles are deleted. People from a directory come back at their next sign-in.')}
          confirm={t('Delete')}
          danger
          onClose={() => setRemove(null)}
          onConfirm={async () => {
            await del(`/api/v1/users/${remove.id}`);
            reload();
          }}
        />
      )}
    </>
  );
}
