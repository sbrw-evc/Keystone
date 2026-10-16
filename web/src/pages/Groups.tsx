import { useState } from 'react';
import { FolderTree, Pencil, Plus, Search, Trash2, UsersRound } from 'lucide-react';
import { del, get, post, put } from '../api/client';
import type { Group, GroupDetail, GroupInput, User } from '../api/types';
import { ActionMenu, Confirm, Empty, ErrorNotice, Field, Loading, Modal, PageHead, Segmented } from '../components/ui';
import { formatDate, useT, type TFn } from '../i18n';
import { isAdmin, useAuth, useLoad } from '../lib/auth';
import { toast } from '../lib/toast';

export function groupSource(s: string, t: TFn) {
  const m: Record<string, string> = { local: t('Keystone'), ldap: 'LDAP / AD', entra: 'Entra ID', google: 'Google', apple: 'Apple', oidc: 'OpenID Connect' };
  return m[s] ?? s;
}

type Source = 'local' | 'ldap' | 'entra';

function GroupDialog({ group, users, onClose, onSaved }: { group: Group | null; users: User[]; onClose: () => void; onSaved: () => void }) {
  const t = useT();
  const [source, setSource] = useState<Source>((group?.source as Source) ?? 'local');
  const [v, setV] = useState<GroupInput>({ name: group?.name ?? '', description: group?.description ?? '', external_id: group?.external_id ?? '' });
  const [members, setMembers] = useState<string[] | null>(group ? null : []);
  const [filter, setFilter] = useState('');
  const [error, setError] = useState<unknown>(null);
  const { error: loadError } = useLoad(async () => {
    if (group && group.source === 'local') setMembers((await get<GroupDetail>(`/api/v1/groups/${group.id}`)).member_ids);
    return null;
  });
  const save = async () => {
    setError(null);
    try {
      const body: GroupInput = { name: v.name, description: v.description };
      if (source === 'local' && members) body.members = members;
      if (!group && source !== 'local') {
        body.source = source;
        body.external_id = v.external_id;
      }
      if (group) await put(`/api/v1/groups/${group.id}`, body);
      else await post('/api/v1/groups', body);
      toast(t('Saved'));
      onSaved();
      onClose();
    } catch (e) {
      setError(e);
    }
  };
  const shown = users.filter((u) => !filter || `${u.username} ${u.name}`.toLowerCase().includes(filter.toLowerCase()));
  return (
    <Modal
      title={group ? t('Edit the group') : t('New group')}
      onClose={onClose}
      width={560}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('Cancel')}
          </button>
          <button type="button" className="btn btn-primary" onClick={save} disabled={!v.name || (!group && source !== 'local' && !v.external_id)}>
            {group ? t('Save') : t('Create')}
          </button>
        </>
      }
    >
      {!group && (
        <Field label={t('Kind')}>
          <Segmented<Source>
            label={t('Kind')}
            value={source}
            onChange={setSource}
            options={[
              { value: 'local', label: t('Keystone group') },
              { value: 'ldap', label: 'LDAP / AD' },
              { value: 'entra', label: 'Entra ID' },
            ]}
          />
        </Field>
      )}
      {source !== 'local' && !group && (
        <div className="notice">
          {source === 'ldap'
            ? t('A directory group gets its members from Active Directory or LDAP at each sign-in. Create it ahead to give it roles before its members first sign in.')
            : t('An Entra group gets its members from Microsoft Entra ID at each sign-in. Create it ahead to give it roles before its members first sign in.')}
        </div>
      )}
      <Field label={t('Name')}>
        <input className="input" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} autoFocus />
      </Field>
      {source === 'ldap' && (
        <Field label={t('Distinguished name (DN)')} hint={group ? undefined : 'CN=NOC,OU=Groups,DC=example,DC=com'}>
          <input className="input mono" value={v.external_id} disabled={!!group} onChange={(e) => setV({ ...v, external_id: e.target.value })} placeholder="CN=…,OU=…,DC=…" />
        </Field>
      )}
      {source === 'entra' && (
        <Field label={t('Object ID of the Entra group')} hint={group ? undefined : t('Microsoft Entra admin center → Groups → the group → Object ID')}>
          <input className="input mono" value={v.external_id} disabled={!!group} onChange={(e) => setV({ ...v, external_id: e.target.value })} placeholder="00000000-0000-0000-0000-000000000000" />
        </Field>
      )}
      <Field label={t('Description')}>
        <input className="input" value={v.description} onChange={(e) => setV({ ...v, description: e.target.value })} />
      </Field>
      {source === 'local' && (
        <Field label={t('Members ({n})', { n: members?.length ?? 0 })}>
          <input className="input input-sm" placeholder={t('Filter people')} value={filter} onChange={(e) => setFilter(e.target.value)} />
          {members === null ? (
            <Loading />
          ) : (
            <div className="member-list">
              {shown.map((u) => (
                <label key={u.id}>
                  <input type="checkbox" checked={members.includes(u.id)} onChange={(e) => setMembers(e.target.checked ? [...members, u.id] : members.filter((m) => m !== u.id))} />
                  <span>
                    {u.name || u.username} <span className="muted small">{u.username}</span>
                  </span>
                </label>
              ))}
            </div>
          )}
        </Field>
      )}
      <ErrorNotice error={error || loadError} />
    </Modal>
  );
}

export function GroupsPage() {
  const t = useT();
  const { account } = useAuth();
  const admin = isAdmin(account);
  const { data, error, reload } = useLoad(() => Promise.all([get<Group[]>('/api/v1/groups'), get<User[]>('/api/v1/users')]));
  const [edit, setEdit] = useState<Group | 'new' | null>(null);
  const [remove, setRemove] = useState<Group | null>(null);
  const [q, setQ] = useState('');
  const [groups, users] = data ?? [[], []];
  const list = groups.filter((g) => !q || `${g.name} ${g.description} ${g.external_id ?? ''}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <PageHead
        title={t('Groups')}
        subtitle={t('Groups of Keystone and groups of the directories. Give a group a role in an application and all its members get it.')}
        actions={
          admin && (
            <button type="button" className="btn btn-primary" onClick={() => setEdit('new')}>
              <Plus size={16} />
              {t('New group')}
            </button>
          )
        }
      />
      <div className="toolbar">
        <div className="search">
          <Search size={16} />
          <input className="input" placeholder={t('Search groups')} value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>
      <ErrorNotice error={error} />
      {!data ? (
        <Loading />
      ) : list.length === 0 ? (
        <div className="card">
          <Empty icon={<UsersRound className="icon" />} title={t('No groups yet')} text={t('Create Keystone groups or add the groups of your directory.')} />
        </div>
      ) : (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('Group')}</th>
                <th>{t('Source')}</th>
                <th>{t('Members')}</th>
                <th>{t('Created')}</th>
                {admin && <th />}
              </tr>
            </thead>
            <tbody>
              {list.map((g) => (
                <tr key={g.id}>
                  <td>
                    <div className="cell-main">
                      <span className="provider-logo">{g.source === 'local' ? <UsersRound size={16} /> : <FolderTree size={16} />}</span>
                      <div>
                        <strong>{g.name}</strong>
                        <small className={g.external_id ? 'mono' : ''}>{g.external_id || g.description || '—'}</small>
                      </div>
                    </div>
                  </td>
                  <td>
                    <span className={`pill ${g.source === 'local' ? '' : 'pill-info'}`}>{groupSource(g.source, t)}</span>
                  </td>
                  <td>{g.members}</td>
                  <td className="nowrap">{formatDate(g.created_at, false)}</td>
                  {admin && (
                    <td className="actions-cell">
                      <ActionMenu label={t('Actions')}>
                        {(close) => (
                          <>
                            <button type="button" className="um-item" onClick={() => (close(), setEdit(g))}>
                              <Pencil size={16} />
                              {t('Edit')}
                            </button>
                            <div className="um-sep" />
                            <button type="button" className="um-item danger" onClick={() => (close(), setRemove(g))}>
                              <Trash2 size={16} />
                              {t('Delete')}
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
      {edit && <GroupDialog group={edit === 'new' ? null : edit} users={users} onClose={() => setEdit(null)} onSaved={reload} />}
      {remove && (
        <Confirm
          title={t('Delete the group {name}?', { name: remove.name })}
          text={t('Its members lose the roles given to the group.')}
          confirm={t('Delete')}
          danger
          onClose={() => setRemove(null)}
          onConfirm={async () => {
            await del(`/api/v1/groups/${remove.id}`);
            reload();
          }}
        />
      )}
    </>
  );
}
