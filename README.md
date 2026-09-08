# onprem-kit

Shared logic for PKI, CAMP and QryptoScan — the parts that must mean the
same thing in every product.

A sibling repo, like `portal-kit`. Clone it BESIDE the product repos:

    ~/Documents/ClaudeProjects/
      PKI/  camp/  qryptoscan/  portal-kit/  onprem-kit/

Products reach it with a `replace` in each service's `go.mod`, the same
arrangement already used for PKI's `pkg/auth` and `pkg/nodelock`.

## Packages

- **`backupdest`** — where a backup is written, and the credential handling that
  goes with it. `Redacted()` MASKS rather than removes, which is right for a log
  line and wrong for anything a form round-trips; see the products' own notes.
- **`serviceurl`** — the configured public URL, and the port arithmetic around it.
- **`hostmatch`** — the hostname questions: does this licence name the address we
  are served on, and does this certificate cover it (RFC 6125, wildcards
  included).
- **`servicecert`** — validates the TLS certificate and key an administrator
  uploads, before anything is written. Turning on TLS recreates the stack, so a
  certificate that turns out to be expired, mismatched or for another hostname
  is otherwise discovered when the gateway will not start — with the product off
  the network and the person who pressed the button unable to reach the screen
  they pressed it on.
- **`pqc`** — the vocabulary CAMP and QryptoScan must share to produce ONE
  CBOM rather than two: the risk enum, CycloneDX's cryptoFunctions, the
  Appendix A §2 table, and — the actual point — `BOMRef`, the identity function
  both products call and neither implements. Types duplicate harmlessly;
  identity does not.

`licence` and `trial` were documented here for some time and are not in this
repository. The list above is what is actually present.

## Why this exists

The three products carried three near-identical copies of licence verification.
They mostly agreed, with one exception that mattered: every licence carries a
`url` claim naming the host it was issued for, and **not one product read it**.

What stays per-product is what must: each has its own vendor signing key, so a
CAMP licence cannot verify against PKI's key. Product confusion is impossible
rather than merely checked for.
