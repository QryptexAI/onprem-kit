package pqc

import (
	"reflect"
	"testing"
)

func TestTLSSuiteAlgorithms(t *testing.T) {
	for name, want := range map[string][]string{
		"TLS_AES_128_GCM_SHA256":                      {"crypto/aes/128", "crypto/sha2/sha256"},
		"TLS_CHACHA20_POLY1305_SHA256":                {"crypto/chacha20", "crypto/sha2/sha256"},
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":       {"crypto/ec", "crypto/rsa", "crypto/aes/256", "crypto/sha2/sha384"},
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":        {"crypto/ec", "crypto/aes/128", "crypto/sha1"},
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":               {"crypto/rsa", "crypto/legacy-symmetric", "crypto/sha1"},
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": {"crypto/ec", "crypto/rsa", "crypto/chacha20", "crypto/sha2/sha256"},
	} {
		if got := TLSSuiteAlgorithms(name); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	if TLSSuiteAlgorithms("not a suite") != nil || !TLSSuiteIsTLS13("TLS_AES_128_GCM_SHA256") || TLSSuiteIsTLS13("TLS_RSA_WITH_AES_128_CBC_SHA") {
		t.Error("parse edges")
	}
}

// SSH's names land on the components TLS and certificates use.
func TestSSHNamesShareComponents(t *testing.T) {
	for name, want := range map[string]string{
		"curve25519-sha256":             "crypto/ec/x25519",
		"ecdh-sha2-nistp256":            "crypto/ec/secp256r1",
		"ecdsa-sha2-nistp384":           "crypto/ec/secp384r1",
		"ssh-ed25519":                   "crypto/ec/ed25519",
		"mlkem768x25519-sha256":         "crypto/hybrid-kem/x25519mlkem768",
		"X25519MLKEM768":                "crypto/hybrid-kem/x25519mlkem768",
		"rsa-sha2-512":                  "crypto/rsa",
		"aes256-gcm@openssh.com":        "crypto/aes/256",
		"chacha20-poly1305@openssh.com": "crypto/chacha20",
		"hmac-sha2-256-etm@openssh.com": "crypto/hmac/sha256",
		"diffie-hellman-group14-sha256": "crypto/dh/modp2048",
	} {
		if got := AlgorithmRefFor(name); got != want {
			t.Errorf("%s -> %s, want %s", name, got, want)
		}
	}
}
