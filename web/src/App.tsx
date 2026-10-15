import type { ReactNode } from 'react';
import { ShieldOff } from 'lucide-react';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { Shell } from './components/Shell';
import { Empty, Loading } from './components/ui';
import { useT } from './i18n';
import { AuthProvider, canAudit, useAuth } from './lib/auth';
import { Toasts } from './lib/toast';
import { ApplicationsPage } from './pages/Applications';
import { AuditPage } from './pages/Audit';
import { DirectoriesPage } from './pages/Directories';
import { GeneralPage } from './pages/General';
import { GroupsPage } from './pages/Groups';
import { HomePage } from './pages/Home';
import { PasswordPolicyPage } from './pages/PasswordPolicy';
import { ProfilePage } from './pages/Profile';
import { ProvidersPage } from './pages/Providers';
import { SignInPage } from './pages/SignIn';
import { UsersPage } from './pages/Users';

/** Pages behind the sign-in; administration pages need the auditor or administrator role. */
function Private({ children, staff }: { children: ReactNode; staff?: boolean }) {
  const t = useT();
  const { account, loading } = useAuth();
  const location = useLocation();
  if (loading) return <Loading />;
  if (!account) return <Navigate to={`/signin?return=${encodeURIComponent(location.pathname + location.search)}`} replace />;
  return (
    <Shell>
      {staff && !canAudit(account) ? (
        <div className="card">
          <Empty icon={<ShieldOff className="icon" />} title={t('Only SPA administrators and auditors see this page')} action={<Link to="/">{t('Home')}</Link>} />
        </div>
      ) : (
        children
      )}
    </Shell>
  );
}

function NotFound() {
  const t = useT();
  return (
    <div className="card">
      <Empty icon={<ShieldOff className="icon" />} title={t('Page not found')} action={<Link to="/">{t('Home')}</Link>} />
    </div>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/signin" element={<SignInPage />} />
          <Route path="/" element={<Private><HomePage /></Private>} />
          <Route path="/profile" element={<Private><ProfilePage /></Private>} />
          <Route path="/users" element={<Private staff><UsersPage /></Private>} />
          <Route path="/groups" element={<Private staff><GroupsPage /></Private>} />
          <Route path="/applications" element={<Private staff><ApplicationsPage /></Private>} />
          <Route path="/audit" element={<Private staff><AuditPage /></Private>} />
          <Route path="/settings" element={<Navigate to="/settings/general" replace />} />
          <Route path="/settings/password-policy" element={<Private staff><PasswordPolicyPage /></Private>} />
          <Route path="/settings/directories" element={<Private staff><DirectoriesPage /></Private>} />
          <Route path="/settings/providers" element={<Private staff><ProvidersPage /></Private>} />
          <Route path="/settings/general" element={<Private staff><GeneralPage /></Private>} />
          <Route path="*" element={<Private><NotFound /></Private>} />
        </Routes>
        <Toasts />
      </AuthProvider>
    </BrowserRouter>
  );
}
