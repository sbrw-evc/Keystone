import { t } from '../i18n';

/** The header every state-changing call must carry (backend CSRFHeader). */
export const CSRF = { 'X-Requested-With': 'spa' };

export class ApiError extends Error {
  status: number;
  code: string;
  violations: string[];
  extra: Record<string, unknown>;
  constructor(status: number, code: string, message: string, violations: string[] = [], extra: Record<string, unknown> = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.violations = violations;
    this.extra = extra;
  }
}

let onUnauthorized: (() => void) | null = null;
/** Called when an API call answers 401 (the session ended). */
export function setUnauthorizedHandler(fn: (() => void) | null) {
  onUnauthorized = fn;
}

export async function api<T>(method: string, path: string, body?: unknown, opts: { quiet401?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (method !== 'GET') Object.assign(headers, CSRF);
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let res: Response;
  try {
    res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin' });
  } catch {
    throw new ApiError(0, 'network', 'Keystone does not answer. Check the connection');
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: unknown = undefined;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    /* not JSON */
  }
  if (!res.ok) {
    const e = (data ?? {}) as { code?: string; message?: string; violations?: string[]; extra?: Record<string, unknown> };
    if (res.status === 401 && !opts.quiet401 && onUnauthorized) onUnauthorized();
    throw new ApiError(res.status, e.code ?? 'error', e.message ?? res.statusText, e.violations ?? [], e.extra ?? {});
  }
  return data as T;
}

export const get = <T>(path: string, opts?: { quiet401?: boolean }) => api<T>('GET', path, undefined, opts);
export const post = <T>(path: string, body: unknown = {}) => api<T>('POST', path, body);
export const put = <T>(path: string, body: unknown) => api<T>('PUT', path, body);
export const patch = <T>(path: string, body: unknown) => api<T>('PATCH', path, body);
export const del = <T = void>(path: string) => api<T>('DELETE', path);

/** Texts of the password policy violation codes (policy.Violation*). */
export function violationText(code: string): string {
  switch (code) {
    case 'length':
      return t('Too short');
    case 'digits':
      return t('Not enough digits');
    case 'special':
      return t('Not enough special characters');
    case 'mixed_case':
      return t('Needs upper- and lower-case letters');
    case 'letters':
      return t('Uses letters the policy does not allow');
    case 'username':
      return t('Contains the user name');
    case 'control':
      return t('Contains control characters');
    case 'common':
      return t('Too common or easy to guess');
    case 'history':
      return t('Was used recently');
  }
  return code;
}

/** A human message for an error, in the current language (server messages are English and translated by key). */
export function describeError(err: unknown): string {
  if (err instanceof ApiError) {
    const msg = t(err.message);
    if (err.violations.length) return `${msg}: ${err.violations.map(violationText).join(', ')}`;
    return msg;
  }
  if (err instanceof DOMException && (err.name === 'NotAllowedError' || err.name === 'AbortError')) return t('The passkey request was cancelled or timed out');
  if (err instanceof Error) return err.message || t('Something went wrong');
  return t('Something went wrong');
}
