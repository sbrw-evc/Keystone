import { afterEach, describe, expect, it, vi } from 'vitest';
import { setLang } from '../i18n';
import { ApiError, api, describeError } from './client';

afterEach(() => {
  vi.unstubAllGlobals();
  setLang('en');
});

describe('api client', () => {
  it('sends the CSRF header on state-changing calls only', async () => {
    const fetch = vi.fn(async () => new Response('{"ok":true}', { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    await api('GET', '/api/v1/me');
    await api('POST', '/api/v1/auth/logout', {});
    const calls = fetch.mock.calls as unknown as [string, RequestInit][];
    expect((calls[0][1].headers as Record<string, string>)['X-Requested-With']).toBeUndefined();
    expect((calls[1][1].headers as Record<string, string>)['X-Requested-With']).toBe('spa');
  });

  it('turns API errors into ApiError with code, violations and extra', async () => {
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ code: 'password_change_required', message: 'Choose a new password to continue', extra: { ticket: 'x' } }), { status: 409 }));
    const err = (await api('POST', '/api/v1/auth/password', {}).catch((e: unknown) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.code).toBe('password_change_required');
    expect(err.extra.ticket).toBe('x');
  });

  it('translates server messages and policy violations', () => {
    setLang('ru');
    const e = new ApiError(400, 'password_policy', 'The password does not meet the password policy', ['length', 'digits']);
    expect(describeError(e)).toBe('Пароль не соответствует парольной политике: Слишком короткий, Мало цифр');
  });
});
