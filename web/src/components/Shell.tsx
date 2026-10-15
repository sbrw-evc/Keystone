import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import {
  AppWindow,
  Check,
  ChevronDown,
  ChevronRight,
  FileClock,
  FolderTree,
  House,
  KeyRound,
  Languages,
  LogOut,
  Menu,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  UserRound,
  Users,
  UsersRound,
  type LucideIcon,
} from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { LANGS, setLang, useLang, useT } from '../i18n';
import { canAudit, useAuth } from '../lib/auth';
import { setTheme, useTheme, type Theme } from '../lib/theme';
import { Avatar, Brand, spring } from './ui';

interface NavPage {
  to: string;
  label: string;
  icon: LucideIcon;
}
interface NavGroup {
  id: string;
  label: string;
  icon: LucideIcon;
  pages: NavPage[];
}

function useNav(): { top: NavPage[]; groups: NavGroup[] } {
  const t = useT();
  const { account } = useAuth();
  const top = [
    { to: '/', label: t('Home'), icon: House },
    { to: '/profile', label: t('Account and security'), icon: UserRound },
  ];
  if (!canAudit(account)) return { top, groups: [] };
  return {
    top,
    groups: [
      {
        id: 'admin',
        label: t('Administration'),
        icon: ShieldCheck,
        pages: [
          { to: '/users', label: t('Users'), icon: Users },
          { to: '/groups', label: t('Groups'), icon: UsersRound },
          { to: '/applications', label: t('Applications'), icon: AppWindow },
          { to: '/audit', label: t('Audit log'), icon: FileClock },
        ],
      },
      {
        id: 'settings',
        label: t('Settings'),
        icon: Settings,
        pages: [
          { to: '/settings/password-policy', label: t('Password policy'), icon: KeyRound },
          { to: '/settings/directories', label: t('Directories'), icon: FolderTree },
          { to: '/settings/providers', label: t('Sign-in providers'), icon: ShieldCheck },
          { to: '/settings/general', label: t('General'), icon: SlidersHorizontal },
        ],
      },
    ],
  };
}

const isActive = (path: string, to: string) => (to === '/' ? path === '/' : path === to || path.startsWith(to + '/'));

function read(key: string) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function write(key: string, v: string) {
  try {
    localStorage.setItem(key, v);
  } catch {
    /* lasts until reload */
  }
}

function SideLink({ page, active, rail }: { page: NavPage; active: boolean; rail: boolean }) {
  const I = page.icon;
  return (
    <Link to={page.to} className={`side-link ${active ? 'active' : ''}`} title={rail ? page.label : undefined} aria-current={active ? 'page' : undefined}>
      {active && <motion.span layoutId="side-pill" className="side-pill" transition={spring} />}
      <I size={18} />
      <span className="side-label">{page.label}</span>
    </Link>
  );
}

function Sidebar({ rail }: { rail: boolean }) {
  const { top, groups } = useNav();
  const { pathname } = useLocation();
  const [open, setOpen] = useState<Record<string, boolean>>(() => Object.fromEntries(groups.map((g) => [g.id, read(`spa.sidebar.${g.id}`) !== '0'])));
  return (
    <nav className={`sidebar ${rail ? 'collapsed' : ''}`} id="app-sidebar">
      <div className="side-group">
        {top.map((p) => (
          <SideLink key={p.to} page={p} active={isActive(pathname, p.to)} rail={rail} />
        ))}
      </div>
      {groups.map((g) => {
        const has = g.pages.some((p) => isActive(pathname, p.to));
        const isOpen = rail || open[g.id] !== false;
        const GI = g.icon;
        return (
          <div className="side-group" key={g.id}>
            {rail ? (
              <div className="side-sep" />
            ) : (
              <button
                type="button"
                className={`side-accordion ${has ? 'has-active' : ''}`}
                aria-expanded={isOpen}
                onClick={() => {
                  const next = !isOpen;
                  setOpen((o) => ({ ...o, [g.id]: next }));
                  write(`spa.sidebar.${g.id}`, next ? '1' : '0');
                }}
              >
                <GI size={18} />
                <span>{g.label}</span>
                <motion.span className="side-chevron" animate={{ rotate: isOpen ? 0 : -90 }} transition={spring}>
                  <ChevronDown size={16} />
                </motion.span>
              </button>
            )}
            <AnimatePresence initial={false}>
              {isOpen && (
                <motion.div className="side-children" initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }}>
                  <div className={rail ? '' : 'side-children-inner'} style={rail ? { display: 'flex', flexDirection: 'column', gap: 2 } : undefined}>
                    {g.pages.map((p) => (
                      <SideLink key={p.to} page={p} active={isActive(pathname, p.to)} rail={rail} />
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        );
      })}
    </nav>
  );
}

function Accordion({ icon, label, value, open, onToggle, options }: { icon: ReactNode; label: string; value: string; open: boolean; onToggle: () => void; options: { key: string; label: string; icon?: ReactNode; selected: boolean; select: () => void }[] }) {
  return (
    <div className={`um-accordion ${open ? 'open' : ''}`}>
      <button type="button" className="um-item" aria-expanded={open} onClick={onToggle}>
        {icon}
        <span className="um-label">{label}</span>
        <span className="um-value">{value}</span>
        <motion.span className="um-chevron" animate={{ rotate: open ? 90 : 0 }} transition={spring}>
          <ChevronRight size={16} />
        </motion.span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div className="um-options" initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.18 }}>
            {options.map((o) => (
              <button key={o.key} type="button" role="menuitemradio" aria-checked={o.selected} className={`um-option ${o.selected ? 'selected' : ''}`} onClick={o.select}>
                {o.icon}
                <span className="um-label">{o.label}</span>
                {o.selected && <Check size={16} />}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

const ROLE_LABEL = { admin: 'Administrator', auditor: 'Auditor', user: 'User' } as const;

function UserMenu() {
  const t = useT();
  const { account, signOut } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useTheme();
  const lang = useLang();
  const [open, setOpen] = useState(false);
  const [section, setSection] = useState<'language' | 'theme' | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const id = useId();
  const name = account?.name || account?.username || '?';

  useEffect(() => setOpen(false), [location.pathname]);
  useEffect(() => {
    if (!open) {
      setSection(null);
      return;
    }
    const onDown = (e: PointerEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('pointerdown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);
  const origin = () => {
    const r = trigger.current?.getBoundingClientRect();
    return r ? { x: r.left + r.width / 2, y: r.top + r.height / 2 } : undefined;
  };
  const roleLabels: Record<string, string> = { admin: t('Administrator'), auditor: t('Auditor'), user: t('User') };

  return (
    <div className="user-menu" ref={root}>
      <button ref={trigger} type="button" className="user-btn" aria-haspopup="menu" aria-expanded={open} aria-controls={id} aria-label={t('Account menu')} onClick={() => setOpen((v) => !v)}>
        <span className="who">
          <strong>{name}</strong>
          <small>{account?.email || account?.username}</small>
        </span>
        <Avatar name={name} />
        <motion.span className="chevron" animate={{ rotate: open ? 180 : 0 }} transition={spring}>
          <ChevronDown size={16} />
        </motion.span>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            id={id}
            role="menu"
            className="user-dropdown"
            initial={{ opacity: 0, y: -8, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -6, scale: 0.98 }}
            transition={{ duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
            style={{ transformOrigin: 'top right' }}
          >
            <div className="menu-head">
              <Avatar name={name} size={44} />
              <div>
                <strong>{name}</strong>
                <small>{account?.email || account?.username}</small>
                <small>{roleLabels[account?.spa_role ?? 'user'] ?? ROLE_LABEL.user}</small>
              </div>
            </div>
            <button type="button" role="menuitem" className="um-item" onClick={() => navigate('/profile')}>
              <ShieldCheck size={18} />
              {t('Account and security')}
            </button>
            <Accordion
              icon={<Languages size={18} />}
              label={t('Language')}
              value={LANGS.find((l) => l.code === lang)?.label ?? lang}
              open={section === 'language'}
              onToggle={() => setSection(section === 'language' ? null : 'language')}
              options={LANGS.map((l) => ({ key: l.code, label: l.label, selected: l.code === lang, select: () => setLang(l.code) }))}
            />
            <Accordion
              icon={theme === 'dark' ? <Moon size={18} /> : <Sun size={18} />}
              label={t('Theme')}
              value={theme === 'dark' ? t('Dark') : t('Light')}
              open={section === 'theme'}
              onToggle={() => setSection(section === 'theme' ? null : 'theme')}
              options={(['light', 'dark'] as Theme[]).map((v) => ({
                key: v,
                label: v === 'dark' ? t('Dark') : t('Light'),
                icon: v === 'dark' ? <Moon size={16} /> : <Sun size={16} />,
                selected: v === theme,
                select: () => setTheme(v, origin()),
              }))}
            />
            <div className="um-sep" />
            <button type="button" role="menuitem" className="um-item danger" onClick={signOut}>
              <LogOut size={18} />
              {t('Sign out')}
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/** The application shell: top bar on the chrome, sidebar, and the page block. */
export function Shell({ children }: { children: ReactNode }) {
  const t = useT();
  const [rail, setRail] = useState(() => read('spa.sidebar.collapsed') === '1');
  const [menu, setMenu] = useState(false);
  const { pathname } = useLocation();
  useEffect(() => setMenu(false), [pathname]);
  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-start">
          <button
            type="button"
            className="icon-btn side-toggle desktop-only"
            aria-label={rail ? t('Expand the menu') : t('Collapse the menu')}
            title={rail ? t('Expand the menu') : t('Collapse the menu')}
            onClick={() =>
              setRail((v) => {
                write('spa.sidebar.collapsed', v ? '0' : '1');
                return !v;
              })
            }
          >
            {rail ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
          </button>
          <button type="button" className="icon-btn side-toggle phone-only" aria-label={t('Menu')} onClick={() => setMenu((v) => !v)}>
            <Menu size={18} />
          </button>
          <Link to="/" className="brand-link">
            <Brand subtitle={t('Single Point of Authorization')} />
          </Link>
        </div>
        <div className="topbar-end">
          <UserMenu />
        </div>
      </header>
      <div className={`app-body ${rail ? 'side-collapsed' : ''} ${menu ? 'menu-open' : ''}`}>
        <Sidebar rail={rail} />
        <main className="app-main">
          <div className="page page-enter" key={pathname}>
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
