package main

import (
	"encoding/binary"

	"github.com/go-webauthn/webauthn/webauthn"
)

type User struct {
	ID          uint64
	Name        string
	Credentials webauthn.Credentials
}

func (u *User) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, u.ID)
	return b
}
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.Name }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type RegistrationCache struct {
	SessionData webauthn.SessionData
	PendingUser *User
}
