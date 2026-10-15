package passkey

import (
	"strings"
	"time"
)

// Passkey is a registered WebAuthn credential of a person.
type Passkey struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	CredentialID []byte `json:"-"`
	PublicKey    []byte `json:"-"`
	// UserHandle is the user ID the authenticator stored with the credential.
	UserHandle     []byte     `json:"-"`
	SignCount      uint32     `json:"-"`
	AAGUID         []byte     `json:"-"`
	Transports     []string   `json:"transports"`
	BackupEligible bool       `json:"backup_eligible"`
	BackupState    bool       `json:"backup_state"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
}

// MaxPasskeys is how many passkeys one person may register.
const MaxPasskeys = 20

// HostWithin tells whether host is the passkey domain rpID or one of its subdomains.
func HostWithin(host, rpID string) bool {
	host, rpID = strings.ToLower(host), strings.ToLower(rpID)
	return rpID != "" && (host == rpID || strings.HasSuffix(host, "."+rpID))
}
