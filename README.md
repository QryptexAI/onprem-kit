# onprem-kit

Shared on-prem licensing, hostname and trial logic for PKI, CAMP and QryptoScan.

A sibling repo, like `portal-kit`. Clone it BESIDE the product repos:

    ~/Documents/ClaudeProjects/
      PKI/  camp/  qryptoscan/  portal-kit/  onprem-kit/

Products reach it with a `replace` in each service's `go.mod`, the same
arrangement already used for PKI's `pkg/auth` and `pkg/nodelock`.

## Packages

- **`licence`** — verify a vendor-signed licence: signature → product → validity
  window → **URL** → node-lock. Per-product identity (vendor key, product
  string, issuer, evaluation caps) is supplied through `Spec`; nothing else
  differs between products.
- **`hostmatch`** — the hostname questions: does this licence name the address we
  are served on, and does this certificate cover it (RFC 6125, wildcards
  included).
- **`servicecert`** — validates the TLS certificate and key an administrator
  uploads, before anything is written. Turning on TLS recreates the stack, so a
  certificate that turns out to be expired, mismatched or for another hostname
  is otherwise discovered when the gateway will not start — with the product off
  the network and the person who pressed the button unable to reach the screen
  they pressed it on.
- **`trial`** — the 30-day clock from first boot, with a high-water mark so
  winding the system clock back does not extend it.
- **`trial/trialtest`** — the conformance suite each product runs against its own
  `trial.Store`. The guarantee that matters — `Start` must not overwrite — cannot
  be tested where the logic lives, because `Begin` only calls `Start` when no
  date exists. A store that upserts passes every test in `trial` and then
  restarts the clock on every boot in production.

## Why this exists

The three products carried three near-identical copies of licence verification.
They mostly agreed, with one exception that mattered: every licence carries a
`url` claim naming the host it was issued for, and **not one product read it**.

What stays per-product is what must: each has its own vendor signing key, so a
CAMP licence cannot verify against PKI's key. Product confusion is impossible
rather than merely checked for.
