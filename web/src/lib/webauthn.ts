// WebAuthn helpers: SPA's begin calls return go-webauthn options ({publicKey: {...}}) with base64url binary
// fields; the finish calls take the browser's credential in the same JSON form.

export function b64urlToBuf(s: string): ArrayBuffer {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

export function bufToB64url(b: ArrayBuffer | null | undefined): string {
  if (!b) return '';
  const bytes = new Uint8Array(b);
  let s = '';
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

type Desc = { id: string; type: string; transports?: string[] };
type Json = Record<string, unknown>;

export function passkeysSupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return (list as Desc[]).map((d) => ({ id: b64urlToBuf(d.id), type: 'public-key', transports: d.transports as AuthenticatorTransport[] | undefined }));
}

/** navigator.credentials.get with options from /api/v1/auth/passkey/begin. */
export async function getAssertion(options: { publicKey: Json }): Promise<Json> {
  const pk = options.publicKey;
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...(pk as object),
    challenge: b64urlToBuf(pk.challenge as string),
    allowCredentials: descriptors(pk.allowCredentials),
  } as PublicKeyCredentialRequestOptions;
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new DOMException('cancelled', 'NotAllowedError');
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      authenticatorData: bufToB64url(r.authenticatorData),
      signature: bufToB64url(r.signature),
      userHandle: r.userHandle ? bufToB64url(r.userHandle) : undefined,
    },
  };
}

/** navigator.credentials.create with options from /api/v1/me/passkeys/begin. */
export async function createCredential(options: { publicKey: Json }): Promise<Json> {
  const pk = options.publicKey;
  const user = pk.user as Json;
  const publicKey = {
    ...(pk as object),
    challenge: b64urlToBuf(pk.challenge as string),
    user: { ...user, id: b64urlToBuf(user.id as string) },
    excludeCredentials: descriptors(pk.excludeCredentials),
  } as PublicKeyCredentialCreationOptions;
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new DOMException('cancelled', 'NotAllowedError');
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      attestationObject: bufToB64url(r.attestationObject),
      transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
    },
  };
}
