// Package authflow is how a person recovers, changes and protects their password in
// every product: the reset link, the "your password was changed" email, the
// in-portal change, the administrator's temporary password with its forced change,
// and authenticator-app (TOTP) multi-factor authentication.
//
// It exists so the three products cannot drift. The flows were redesigned once,
// together, on 2026-10-30; before that PKI reset a password the moment anyone typed
// an address into "Forgot password?" (so anyone could lock anyone out) while CAMP
// had no self-service reset at all and showed administrators a permanent password.
//
// Every step happens in the product's own portal. Keycloak is reached only through
// its admin and token APIs, never through its pages: a Keycloak screen mid-sign-in
// means the customer has visibly left the product.
//
// What the products supply is what genuinely differs between them — how to reach
// Keycloak (Realm), where reset tokens live (TokenStore), how mail is sent
// (Service.Send) and who the signed-in caller is (Handlers.Caller). The behaviour,
// the wording of every email and the HTTP contract the portal-kit screens call are
// all here.
package authflow
