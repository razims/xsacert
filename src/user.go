package main

import (
	"crypto"
	"github.com/go-acme/lego/v3/registration"
)

type CertUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *CertUser) GetEmail() string {
	return u.Email
}
func (u CertUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *CertUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
