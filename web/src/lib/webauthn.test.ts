import { describe, expect, it } from 'vitest';
import { b64urlToBuf, bufToB64url } from './webauthn';

describe('base64url', () => {
  it('round-trips binary data', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const s = bufToB64url(bytes.buffer);
    expect(s).not.toMatch(/[+/=]/);
    expect(new Uint8Array(b64urlToBuf(s))).toEqual(bytes);
  });
});
