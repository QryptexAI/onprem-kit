package pqc

import "strings"

// TLSSuiteAlgorithms names the algorithm components a TLS cipher suite uses, by
// its IANA name, for a protocol component's cipherSuites[].algorithms.
//
//	TLS_AES_128_GCM_SHA256                  aes/128, sha2/sha256 (TLS 1.3: no key exchange in the name)
//	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   ec, rsa, aes/128, sha2/sha256
//
// The key exchange of a TLS 1.2 suite names a family, not a curve: the curve is
// the negotiated group, its own component. An unrecognised part is left out
// rather than guessed; a suite whose name does not parse gets nil.
func TLSSuiteAlgorithms(name string) []string {
	n := strings.ToUpper(strings.TrimSpace(name))
	if !strings.HasPrefix(n, "TLS_") {
		return nil
	}
	n = strings.TrimPrefix(n, "TLS_")
	var parts []string
	if kx, rest, ok := strings.Cut(n, "_WITH_"); ok {
		for _, p := range strings.Split(kx, "_") {
			switch p {
			case "ECDHE", "ECDH":
				parts = append(parts, "ECDH")
			case "DHE", "DH":
				parts = append(parts, "DH")
			case "RSA":
				parts = append(parts, "RSA")
			case "ECDSA":
				parts = append(parts, "ECDSA")
			}
		}
		n = rest
	}
	cipher, mac := splitCipherMAC(n)
	if cipher != "" {
		parts = append(parts, cipher)
	}
	if mac != "" {
		parts = append(parts, mac)
	}
	var refs []string
	seen := map[string]bool{}
	for _, p := range parts {
		if a, ok := Normalise(p); ok {
			if r := BOMRef(a); !seen[r] {
				seen[r] = true
				refs = append(refs, r)
			}
		}
	}
	return refs
}

// splitCipherMAC reads "AES_128_GCM_SHA256" as AES-128 and SHA-256.
func splitCipherMAC(s string) (cipher, mac string) {
	f := strings.Split(s, "_")
	if len(f) == 0 {
		return "", ""
	}
	switch last := f[len(f)-1]; last {
	case "SHA256", "SHA384", "SHA512":
		mac = "SHA-" + last[3:]
		f = f[:len(f)-1]
	case "SHA":
		mac = "SHA-1"
		f = f[:len(f)-1]
	case "MD5":
		mac = "MD5"
		f = f[:len(f)-1]
	}
	switch {
	case len(f) >= 2 && f[0] == "AES":
		cipher = "AES-" + f[1]
	case len(f) >= 1 && f[0] == "CHACHA20":
		cipher = "ChaCha20-Poly1305"
	case len(f) >= 1 && (f[0] == "3DES" || f[0] == "DES" || f[0] == "RC4"):
		cipher = "DES/3DES/RC4"
	}
	return cipher, mac
}

// TLSSuiteIsTLS13 says whether a suite belongs to TLS 1.3, whose names carry no
// key exchange ("TLS_AES_128_GCM_SHA256"), unlike every earlier version's
// ("..._WITH_...").
func TLSSuiteIsTLS13(name string) bool {
	n := strings.ToUpper(name)
	return strings.HasPrefix(n, "TLS_") && !strings.Contains(n, "_WITH_")
}
