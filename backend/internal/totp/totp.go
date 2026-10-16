// Package totp is the second factor of password sign-in: time-based one-time passwords (RFC 6238 over the HOTP of
// RFC 4226; HMAC-SHA1, 30-second steps, 6 digits — what every authenticator app understands) and one-time recovery
// codes.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 with SHA-1 is what authenticator apps implement
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Period is the length of a time step.
	Period = 30
	// Digits is the length of a code.
	Digits = 6
	// Skew is how many steps before and after the current one are accepted (clock drift, typing time).
	Skew = 1
	// SecretBytes is the size of a secret (160 bits, as RFC 4226 recommends).
	SecretBytes = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random secret, base32 without padding (how authenticator apps take it).
func NewSecret() string {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

// ErrSecret: the secret is not base32.
var ErrSecret = errors.New("totp: the secret is not valid base32")

func decode(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimRight(secret, "="), " ", ""))
	k, err := b32.DecodeString(s)
	if err != nil || len(k) == 0 {
		return nil, ErrSecret
	}
	return k, nil
}

// hotp is RFC 4226 §5.3 (dynamic truncation) with HMAC-SHA1.
func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// Step is the time step of t.
func Step(t time.Time) int64 { return t.Unix() / Period }

// Code is the code of the secret at t.
func Code(secret string, t time.Time) (string, error) {
	k, err := decode(secret)
	if err != nil {
		return "", err
	}
	return hotp(k, uint64(Step(t)), Digits), nil
}

// Check tells whether code is the code of the secret at now (± Skew steps) and returns the step it matched; a
// caller keeps the last accepted step so that a code is never accepted twice.
func Check(secret, code string, now time.Time) (int64, bool) {
	code = Normalize(code)
	if len(code) != Digits {
		return 0, false
	}
	k, err := decode(secret)
	if err != nil {
		return 0, false
	}
	cur := Step(now)
	var found int64
	ok := 0
	for d := int64(-Skew); d <= Skew; d++ {
		s := cur + d
		if subtle.ConstantTimeCompare([]byte(hotp(k, uint64(s), Digits)), []byte(code)) == 1 && ok == 0 {
			found, ok = s, 1
		}
	}
	return found, ok == 1
}

// Normalize drops the spaces and dashes people type into codes.
func Normalize(code string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, strings.TrimSpace(code))
}

// IsCode tells whether s looks like a code of an authenticator app (digits only).
func IsCode(s string) bool {
	s = Normalize(s)
	if len(s) != Digits {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// URI is the otpauth:// address an authenticator app reads from the QR code (Key Uri Format).
func URI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {fmt.Sprint(Digits)}, "period": {fmt.Sprint(Period)}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// ---- recovery codes

// RecoveryCount is how many recovery codes a person gets.
const RecoveryCount = 10

// recoveryAlphabet has no look-alike characters (0/o, 1/l/i).
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

const recoveryLen = 10

// NewRecoveryCodes returns n codes of 10 characters (about 49 bits each), shown as xxxxx-xxxxx.
func NewRecoveryCodes(n int) []string {
	out := make([]string, n)
	buf := make([]byte, recoveryLen)
	for i := range out {
		var b strings.Builder
		for j := 0; j < recoveryLen; {
			if _, err := rand.Read(buf); err != nil {
				panic(err)
			}
			for _, x := range buf {
				// rejection sampling keeps the characters uniform
				if int(x) >= 256-256%len(recoveryAlphabet) || j == recoveryLen {
					continue
				}
				if j == recoveryLen/2 {
					b.WriteByte('-')
				}
				b.WriteByte(recoveryAlphabet[int(x)%len(recoveryAlphabet)])
				j++
			}
		}
		out[i] = b.String()
	}
	return out
}

// NormalizeRecovery turns what a person typed into the stored form of a recovery code; ok is false when it cannot
// be one.
func NormalizeRecovery(s string) (string, bool) {
	s = strings.ToLower(Normalize(s))
	if len(s) != recoveryLen {
		return "", false
	}
	for _, r := range s {
		if !strings.ContainsRune(recoveryAlphabet, r) {
			return "", false
		}
	}
	return s, true
}
