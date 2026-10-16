import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Activity, AlertTriangle, Boxes, Eye, EyeOff, LoaderCircle, Moon, MoreHorizontal, Network, RadioTower, Server, Sun, X } from 'lucide-react';
import { AnimatePresence, motion, type Transition } from 'motion/react';
import { describeError } from '../api/client';
import type { AppType } from '../api/types';
import { setLang, useLang, useT, type Lang } from '../i18n';
import { originOf, setTheme, useTheme } from '../lib/theme';

/** The spring Beacon uses for pills, chevrons and dialogs. */
export const spring: Transition = { type: 'spring', stiffness: 420, damping: 30 };

export function Brand({ subtitle, compact }: { subtitle?: string; compact?: boolean }) {
  return (
    <span className="brand">
      <img src="/logo.svg" alt="" width={32} height={32} />
      {!compact && (
        <span>
          <span className="brand-name">Keystone</span>
          {subtitle && <span className="brand-sub"> · {subtitle}</span>}
        </span>
      )}
    </span>
  );
}

export function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void; label: string }) {
  const group = useId();
  return (
    <div className="segmented has-pill" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" role="radio" aria-checked={value === o.value} className={value === o.value ? 'active' : ''} onClick={() => onChange(o.value)}>
          {value === o.value && <motion.span layoutId={`seg-${group}`} className="seg-pill" transition={spring} />}
          <span className="seg-label">{o.label}</span>
        </button>
      ))}
    </div>
  );
}

export function ThemeToggle() {
  const t = useT();
  const theme = useTheme();
  return (
    <button type="button" className="icon-btn" aria-label={t('Switch theme')} title={t('Switch theme')} onClick={(e) => setTheme(theme === 'dark' ? 'light' : 'dark', originOf(e))}>
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={theme}
          style={{ display: 'inline-flex' }}
          initial={{ rotate: -90, scale: 0.4, opacity: 0 }}
          animate={{ rotate: 0, scale: 1, opacity: 1 }}
          exit={{ rotate: 90, scale: 0.4, opacity: 0 }}
          transition={{ duration: 0.22 }}
        >
          {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
        </motion.span>
      </AnimatePresence>
    </button>
  );
}

/** Language (EN / RU) and theme switches of the sign-in page. */
export function Preferences() {
  const t = useT();
  const lang = useLang();
  return (
    <div className="prefs">
      <Segmented<Lang>
        label={t('Language')}
        value={lang}
        onChange={setLang}
        options={[
          { value: 'en', label: 'EN' },
          { value: 'ru', label: 'RU' },
        ]}
      />
      <ThemeToggle />
    </div>
  );
}

export function PageHead({ title, subtitle, actions, icon }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>
          {icon}
          {title}
        </h1>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      {actions && <div className="page-head-actions">{actions}</div>}
    </div>
  );
}

export function Modal({ title, onClose, children, footer, width = 520 }: { title?: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; width?: number | string }) {
  const t = useT();
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeRef.current();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  return createPortal(
    <motion.div
      className="modal-backdrop"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.16 }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <motion.div className="modal" style={{ width }} role="dialog" aria-modal="true" initial={{ opacity: 0, y: 16, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={spring}>
        {title !== undefined && (
          <div className="modal-header">
            <div className="modal-title">{title}</div>
            <button type="button" className="icon-btn" onClick={onClose} aria-label={t('Close')}>
              <X size={18} />
            </button>
          </div>
        )}
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </motion.div>
    </motion.div>,
    document.body,
  );
}

/** A confirmation dialog; destructive ones say that the action cannot be undone. */
export function Confirm({ title, text, confirm, danger, onConfirm, onClose }: { title: string; text: ReactNode; confirm: string; danger?: boolean; onConfirm: () => Promise<unknown> | void; onClose: () => void }) {
  const t = useT();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  return (
    <Modal
      title={title}
      onClose={onClose}
      width={460}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('Cancel')}
          </button>
          <button
            type="button"
            className={`btn ${danger ? 'btn-danger' : 'btn-primary'}`}
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await onConfirm();
                onClose();
              } catch (e) {
                setError(e);
                setBusy(false);
              }
            }}
          >
            {busy && <LoaderCircle size={16} className="spin" />}
            {confirm}
          </button>
        </>
      }
    >
      <div className={`confirm-text ${danger ? 'confirm-danger' : ''}`}>
        {danger && <AlertTriangle size={22} />}
        <div className="stack" style={{ gap: 6 }}>
          <p>{text}</p>
          {danger && <p className="muted">{t('This cannot be undone.')}</p>}
        </div>
      </div>
      <ErrorNotice error={error} />
    </Modal>
  );
}

export function Switch({ checked, onChange, label, hint, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: ReactNode; hint?: ReactNode; disabled?: boolean }) {
  return (
    <label className="switch-row">
      <span className="switch">
        <input type="checkbox" role="switch" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
        <span className="switch-track" />
      </span>
      <span>
        <strong style={{ fontWeight: 600 }}>{label}</strong>
        {hint && <span className="hint">{hint}</span>}
      </span>
    </label>
  );
}

export function Field({ label, hint, children }: { label: ReactNode; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="field">
      <label className="field">
        <span className="field-label" style={{ margin: 0 }}>
          {label}
        </span>
        {children}
      </label>
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

export function PasswordInput({ value, onChange, autoComplete, autoFocus, id, placeholder }: { value: string; onChange: (v: string) => void; autoComplete?: string; autoFocus?: boolean; id?: string; placeholder?: string }) {
  const t = useT();
  const [show, setShow] = useState(false);
  return (
    <div className="password">
      <input id={id} className="input" type={show ? 'text' : 'password'} value={value} onChange={(e) => onChange(e.target.value)} autoComplete={autoComplete} autoFocus={autoFocus} placeholder={placeholder} />
      <button type="button" className="icon-btn" onClick={() => setShow((v) => !v)} aria-label={show ? t('Hide password') : t('Show password')} title={show ? t('Hide password') : t('Show password')}>
        {show ? <EyeOff size={16} /> : <Eye size={16} />}
      </button>
    </div>
  );
}

const AVATAR_COLORS = ['#65a30d', '#ca8a04', '#0d9488', '#2563eb', '#7c3aed', '#db2777', '#ea580c', '#16a34a'];

export function initialsOf(name: string) {
  const parts = name.trim().split(/[\s@._-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '?') + (parts[1]?.[0] ?? '')).toUpperCase();
}

export function Avatar({ name, size = 32 }: { name: string; size?: number }) {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return (
    <span className="avatar" style={{ width: size, height: size, fontSize: Math.round(size * 0.38), background: AVATAR_COLORS[h % AVATAR_COLORS.length] }} aria-hidden>
      {initialsOf(name)}
    </span>
  );
}

export function Loading() {
  const t = useT();
  return (
    <div className="view-loading">
      <LoaderCircle size={20} className="spin" /> {t('Loading…')}
    </div>
  );
}

export function ErrorNotice({ error }: { error: unknown }) {
  if (!error) return null;
  return <div className="notice notice-error">{describeError(error)}</div>;
}

export function Empty({ icon, title, text, action }: { icon: ReactNode; title: string; text?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty-state">
      {icon}
      <h3>{title}</h3>
      {text && <p>{text}</p>}
      {action}
    </div>
  );
}

const APP_ICONS: Record<AppType, typeof Boxes> = {
  beacon: RadioTower,
  current: Activity,
  ledger: Server,
  'network-control': Network,
  oidc: Boxes,
};

export function AppIcon({ type, small }: { type: AppType; small?: boolean }) {
  const I = APP_ICONS[type] ?? Boxes;
  return (
    <span className={`app-icon app-${type} ${small ? 'app-icon-sm' : ''}`} aria-hidden>
      <I size={small ? 17 : 22} strokeWidth={2.2} />
    </span>
  );
}

/** Small logos of the sign-in providers (simple marks, no brand assets). */
export function ProviderMark({ kind }: { kind: string }) {
  switch (kind) {
    case 'entra':
      return (
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden>
          <rect x="2" y="2" width="9.5" height="9.5" fill="#f25022" />
          <rect x="12.5" y="2" width="9.5" height="9.5" fill="#7fba00" />
          <rect x="2" y="12.5" width="9.5" height="9.5" fill="#00a4ef" />
          <rect x="12.5" y="12.5" width="9.5" height="9.5" fill="#ffb900" />
        </svg>
      );
    case 'google':
      return (
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden>
          <path fill="#4285F4" d="M22.6 12.2c0-.8-.1-1.5-.2-2.2H12v4.2h5.9a5 5 0 0 1-2.2 3.3v2.7h3.6c2.1-1.9 3.3-4.8 3.3-8z" />
          <path fill="#34A853" d="M12 23c3 0 5.5-1 7.3-2.7l-3.6-2.7c-1 .7-2.2 1.1-3.7 1.1-2.9 0-5.3-1.9-6.2-4.5H2.1v2.8A11 11 0 0 0 12 23z" />
          <path fill="#FBBC05" d="M5.8 14.2a6.6 6.6 0 0 1 0-4.3V7.1H2.1a11 11 0 0 0 0 9.9z" />
          <path fill="#EA4335" d="M12 5.4c1.6 0 3.1.6 4.2 1.7l3.2-3.2A11 11 0 0 0 2.1 7.1l3.7 2.8C6.7 7.3 9.1 5.4 12 5.4z" />
        </svg>
      );
    case 'apple':
      return (
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden fill="currentColor">
          <path d="M16.4 12.6c0-2.6 2.1-3.8 2.2-3.9-1.2-1.8-3.1-2-3.7-2-1.6-.2-3.1.9-3.9.9-.8 0-2-.9-3.4-.9-1.7 0-3.3 1-4.2 2.6-1.8 3.1-.5 7.7 1.3 10.2.9 1.2 1.9 2.6 3.2 2.6 1.3-.1 1.8-.8 3.3-.8 1.6 0 2 .8 3.4.8 1.4 0 2.3-1.3 3.1-2.5 1-1.4 1.4-2.8 1.4-2.9-.1 0-2.7-1-2.7-4.1zM13.9 5c.7-.9 1.2-2 1-3.2-1 0-2.3.7-3 1.6-.7.8-1.2 2-1.1 3.1 1.2.1 2.3-.6 3.1-1.5z" />
        </svg>
      );
  }
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
      <circle cx="12" cy="12" r="9" />
      <path d="M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18M3 12h18" />
    </svg>
  );
}

export function Copy({ value, label }: { value: string; label?: string }) {
  const t = useT();
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1600);
        } catch {
          /* the text stays selectable */
        }
      }}
    >
      {done ? t('Copied') : (label ?? t('Copy'))}
    </button>
  );
}

/** A drop-down menu of actions next to a button, in a portal so tables do not clip it. */
export function ActionMenu({ label, children }: { label: string; children: (close: () => void) => ReactNode }) {
  const [pos, setPos] = useState<{ top: number; right: number } | null>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!pos) return;
    const onDown = (e: PointerEvent) => {
      if (!menu.current?.contains(e.target as Node) && !btn.current?.contains(e.target as Node)) setPos(null);
    };
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setPos(null);
    const close = () => setPos(null);
    document.addEventListener('pointerdown', onDown);
    document.addEventListener('keydown', onKey);
    window.addEventListener('resize', close);
    document.addEventListener('scroll', close, true);
    return () => {
      document.removeEventListener('pointerdown', onDown);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('resize', close);
      document.removeEventListener('scroll', close, true);
    };
  }, [pos]);
  return (
    <>
      <button
        ref={btn}
        type="button"
        className="icon-btn"
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={!!pos}
        onClick={() => {
          if (pos) return setPos(null);
          const r = btn.current!.getBoundingClientRect();
          setPos({ top: r.bottom + 6, right: window.innerWidth - r.right });
        }}
      >
        <MoreHorizontal size={18} />
      </button>
      {pos &&
        createPortal(
          <motion.div
            ref={menu}
            role="menu"
            className="user-dropdown"
            style={{ position: 'fixed', top: pos.top, right: pos.right, width: 250, transformOrigin: 'top right' }}
            initial={{ opacity: 0, y: -6, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ duration: 0.14 }}
          >
            {children(() => setPos(null))}
          </motion.div>,
          document.body,
        )}
    </>
  );
}
