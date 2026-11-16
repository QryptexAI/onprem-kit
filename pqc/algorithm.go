package pqc

import "strings"

// Family is a normalised algorithm family — the level at which the two products
// can agree.
//
// QryptoScan reads a rule label out of a pack; CAMP reads a precise IANA name
// off the wire. "ECC" and "secp256r1" are the same family and are not the same
// component, which is the distinction Algorithm exists to keep.
type Family string

const (
	FamilyRSA    Family = "rsa"
	FamilyEC     Family = "ec" // ECDSA and ECDH share a curve family
	FamilyDH     Family = "dh"
	FamilyDSA    Family = "dsa"
	FamilyMQV    Family = "mqv"
	FamilyMLKEM  Family = "ml-kem"
	FamilyMLDSA  Family = "ml-dsa"
	FamilySLHDSA Family = "slh-dsa"
	// FamilyHybridKEM is a classical exchange combined with a PQC KEM. Every
	// post-quantum group deployed in practice today is one of these.
	FamilyHybridKEM Family = "hybrid-kem"
	// FamilyHybridSig is a composite signature: a classical key and an ML-DSA
	// key under one algorithm identifier, both signatures required. PKI issues
	// these (the oqs-provider composites).
	FamilyHybridSig Family = "hybrid-sig"
	FamilyAES       Family = "aes"
	FamilySHA1      Family = "sha1"
	FamilySHA2      Family = "sha2"
	FamilyMD5       Family = "md5"
	FamilyLegacySym Family = "legacy-symmetric" // DES, 3DES, RC4, Blowfish
	FamilyPRNG      Family = "prng"
	// FamilyChaCha20 is ChaCha20-Poly1305, the other TLS 1.3 and SSH cipher.
	FamilyChaCha20 Family = "chacha20"
	// FamilyHMAC is a keyed hash; the parameter is the hash. Its strength is the
	// hash's, and Grover does not break it.
	FamilyHMAC Family = "hmac"
	// FamilyUnknown is what a native name that is not in the table becomes.
	// It is a real component, not an error — see Assess.
	FamilyUnknown Family = "unknown"
)

// Algorithm is a normalised cryptographic identity.
type Algorithm struct {
	Family Family
	// Parameter narrows the family: a curve, a modulus size, a parameter set.
	//
	// EMPTY IS MEANINGFUL AND IS NOT A DEFECT. QryptoScan sees
	// KeyPairGenerator.getInstance("EC") and cannot know the curve; CAMP sees
	// secp256r1 on a wire. The unparameterised one is a COARSER COMPONENT, and
	// it is never merged into a specific one — asserting they are the same is a
	// fabrication that would make an agency's count wrong in a document they
	// submit. See BOMRef.
	Parameter string
	// Native is the name the product used, kept so a document can show what was
	// actually observed rather than only our normalisation of it.
	Native string
}

// Profile is what Appendix A §2 and the NIST standards say about a family.
type Profile struct {
	Family Family
	Risk   Risk
	// Functions is what the family DOES, not what a particular call site did.
	Functions []Function
	// MemoRow is the Appendix A §2 row this family answers to. Empty when the
	// family is not in the memo's table — symmetric ciphers and hashes are real
	// findings and are not on it.
	MemoRow string
	Specs   []string
	// Asymmetric drives the memo's fail-closed default. See Assess.
	Asymmetric bool
}

// profiles is a Go table rather than an embedded data file, deliberately.
//
// The design argued for data so that CISA extending Appendix A §2 would not
// need a release of three repositories. That reasoning does not survive
// contact: the RULES are what detect an algorithm, they ship inside the scanner
// image, and they need a release regardless. A hot-loadable table would buy
// nothing while the thing it describes cannot move. If a runtime override is
// ever genuinely needed, it can be added behind this function without changing
// a caller.
var profiles = map[Family]Profile{
	FamilyRSA: {FamilyRSA, QuantumBroken,
		[]Function{KeyGen, Sign, Verify, Encrypt, Decrypt},
		"RSA Signature Algorithm; RSA Key Establishment",
		[]string{"FIPS 186-5", "NIST SP 800-56B rev1"}, true},
	FamilyEC: {FamilyEC, QuantumBroken,
		[]Function{KeyGen, Sign, Verify, KeyDerive},
		"ECDSA; Elliptic Curve Diffie-Hellman (ECDH)",
		[]string{"FIPS 186-5", "NIST SP 800-56A rev3"}, true},
	FamilyDH: {FamilyDH, QuantumBroken, []Function{KeyGen, KeyDerive},
		"Diffie-Hellman (DH) Key Exchange and variants",
		[]string{"NIST SP 800-56A rev3"}, true},
	FamilyDSA: {FamilyDSA, QuantumBroken, []Function{KeyGen, Sign, Verify},
		"Digital Signature Algorithm", []string{"FIPS 186-5"}, true},
	FamilyMQV: {FamilyMQV, QuantumBroken, []Function{KeyGen, KeyDerive},
		"Menezes-Qu-Vanstone (MQV) Key Exchange",
		[]string{"NIST SP 800-56A rev3"}, true},

	FamilyMLKEM: {FamilyMLKEM, PQCReady, []Function{KeyGen, Encapsulate, Decapsulate},
		"", []string{"FIPS 203"}, true},
	FamilyMLDSA: {FamilyMLDSA, PQCReady, []Function{KeyGen, Sign, Verify},
		"", []string{"FIPS 204"}, true},
	FamilySLHDSA: {FamilySLHDSA, PQCReady, []Function{KeyGen, Sign, Verify},
		"", []string{"FIPS 205"}, true},
	// A hybrid is no weaker than its classical half even if the KEM is later
	// broken, which is the whole argument for deploying one — App. A §3.
	FamilyHybridKEM: {FamilyHybridKEM, PQCReady, []Function{KeyGen, Encapsulate, Decapsulate},
		"", []string{"FIPS 203", "NIST IR 8547"}, true},
	// The same argument for signatures: forging one needs both halves broken.
	FamilyHybridSig: {FamilyHybridSig, PQCReady, []Function{KeyGen, Sign, Verify},
		"", []string{"FIPS 204", "NIST IR 8547"}, true},

	FamilyAES:  {FamilyAES, NotApplicable, []Function{Encrypt, Decrypt}, "", nil, false},
	FamilySHA2: {FamilySHA2, NotApplicable, []Function{Digest}, "", nil, false},
	// Grover halves a hash's effective strength; SHA-1 was already too short.
	FamilySHA1: {FamilySHA1, QuantumWeakened, []Function{Digest}, "", nil, false},
	FamilyMD5:  {FamilyMD5, NotApplicable, []Function{Digest}, "", nil, false},
	FamilyLegacySym: {FamilyLegacySym, NotApplicable, []Function{Encrypt, Decrypt},
		"", nil, false},
	FamilyPRNG: {FamilyPRNG, NotApplicable, []Function{Other}, "", nil, false},
	FamilyChaCha20: {FamilyChaCha20, NotApplicable, []Function{Encrypt, Decrypt, Tag},
		"", []string{"RFC 8439"}, false},
	FamilyHMAC: {FamilyHMAC, NotApplicable, []Function{Tag}, "", []string{"FIPS 198-1"}, false},
}

// ProfileFor returns what is known about a family.
func ProfileFor(f Family) (Profile, bool) { p, ok := profiles[f]; return p, ok }

// native maps what each product actually calls things onto a shared identity.
//
// It maps to a full Algorithm rather than to a family, because whether a name
// carries a PARAMETER is a property of the name and not of the family. "ECC"
// and "secp256r1" are both FamilyEC; only the second names a curve. A
// family-level flag got this wrong in both directions — it made every EC label
// look like a specific curve, so a bare "ECC" and a bare "ECDSA" became two
// different components and neither matched the curve CAMP had actually seen.
//
// Both products' spellings live in one table on purpose. Two normalisation
// tables would drift on the first algorithm either product learned, which is
// the same failure as two vocabularies wearing a different hat.
var native = map[string]Algorithm{
	// QryptoScan rule labels (qs-algorithm) — family labels, no parameter.
	"rsa":   {Family: FamilyRSA},
	"ecc":   {Family: FamilyEC},
	"ec":    {Family: FamilyEC},
	"ecdsa": {Family: FamilyEC},
	"ecdh":  {Family: FamilyEC},
	"dh":    {Family: FamilyDH},
	"dsa":   {Family: FamilyDSA},
	"mqv":   {Family: FamilyMQV},
	"md5":   {Family: FamilyMD5},
	"sha-1": {Family: FamilySHA1},
	"sha1":  {Family: FamilySHA1},
	// AES-ECB names a mode, not a key size. The mode is the finding and the
	// family is the component; the mode travels as a property.
	"aes-ecb": {Family: FamilyAES},
	"ecdhe":   {Family: FamilyEC},
	"dhe":     {Family: FamilyDH},

	// ChaCha20-Poly1305, as TLS and SSH name it.
	"chacha20poly1305":              {Family: FamilyChaCha20},
	"chacha20-poly1305":             {Family: FamilyChaCha20},
	"chacha20-poly1305@openssh.com": {Family: FamilyChaCha20},

	// SSH's own names (RFC 4253, 5656, 8731, 9142 and OpenSSH's), mapped onto the
	// components TLS and certificates already use, so one curve or one hybrid is one
	// component whichever protocol carries it.
	"curve25519-sha256":                    {Family: FamilyEC, Parameter: "x25519"},
	"curve25519-sha256@libssh.org":         {Family: FamilyEC, Parameter: "x25519"},
	"ecdh-sha2-nistp256":                   {Family: FamilyEC, Parameter: "secp256r1"},
	"ecdh-sha2-nistp384":                   {Family: FamilyEC, Parameter: "secp384r1"},
	"ecdh-sha2-nistp521":                   {Family: FamilyEC, Parameter: "secp521r1"},
	"diffie-hellman-group1-sha1":           {Family: FamilyDH, Parameter: "modp1024"},
	"diffie-hellman-group14-sha1":          {Family: FamilyDH, Parameter: "modp2048"},
	"diffie-hellman-group14-sha256":        {Family: FamilyDH, Parameter: "modp2048"},
	"diffie-hellman-group16-sha512":        {Family: FamilyDH, Parameter: "modp4096"},
	"diffie-hellman-group18-sha512":        {Family: FamilyDH, Parameter: "modp8192"},
	"diffie-hellman-group-exchange-sha1":   {Family: FamilyDH},
	"diffie-hellman-group-exchange-sha256": {Family: FamilyDH},
	"mlkem768x25519-sha256":                {Family: FamilyHybridKEM, Parameter: "x25519mlkem768"},
	"sntrup761x25519-sha512":               {Family: FamilyHybridKEM, Parameter: "sntrup761x25519"},
	"sntrup761x25519-sha512@openssh.com":   {Family: FamilyHybridKEM, Parameter: "sntrup761x25519"},
	"ssh-ed25519":                          {Family: FamilyEC, Parameter: "ed25519"},
	"ssh-ed448":                            {Family: FamilyEC, Parameter: "ed448"},
	"ssh-rsa":                              {Family: FamilyRSA},
	"rsa-sha2-256":                         {Family: FamilyRSA},
	"rsa-sha2-512":                         {Family: FamilyRSA},
	"ssh-dss":                              {Family: FamilyDSA},
	"ecdsa-sha2-nistp256":                  {Family: FamilyEC, Parameter: "secp256r1"},
	"ecdsa-sha2-nistp384":                  {Family: FamilyEC, Parameter: "secp384r1"},
	"ecdsa-sha2-nistp521":                  {Family: FamilyEC, Parameter: "secp521r1"},
	"aes128-ctr":                           {Family: FamilyAES, Parameter: "128"},
	"aes192-ctr":                           {Family: FamilyAES, Parameter: "192"},
	"aes256-ctr":                           {Family: FamilyAES, Parameter: "256"},
	"aes128-gcm@openssh.com":               {Family: FamilyAES, Parameter: "128"},
	"aes256-gcm@openssh.com":               {Family: FamilyAES, Parameter: "256"},
	"aes128-cbc":                           {Family: FamilyAES, Parameter: "128"},
	"aes256-cbc":                           {Family: FamilyAES, Parameter: "256"},
	"3des-cbc":                             {Family: FamilyLegacySym, Parameter: "3des"},
	"hmac-sha1":                            {Family: FamilyHMAC, Parameter: "sha1"},
	"hmac-sha1-etm@openssh.com":            {Family: FamilyHMAC, Parameter: "sha1"},
	"hmac-sha2-256":                        {Family: FamilyHMAC, Parameter: "sha256"},
	"hmac-sha2-256-etm@openssh.com":        {Family: FamilyHMAC, Parameter: "sha256"},
	"hmac-sha2-512":                        {Family: FamilyHMAC, Parameter: "sha512"},
	"hmac-sha2-512-etm@openssh.com":        {Family: FamilyHMAC, Parameter: "sha512"},
	"hmac-md5":                             {Family: FamilyHMAC, Parameter: "md5"},
	"umac-64@openssh.com":                  {Family: FamilyHMAC, Parameter: "umac64"},
	"umac-128@openssh.com":                 {Family: FamilyHMAC, Parameter: "umac128"},
	"umac-64-etm@openssh.com":              {Family: FamilyHMAC, Parameter: "umac64"},
	"umac-128-etm@openssh.com":             {Family: FamilyHMAC, Parameter: "umac128"},
	"prng":                                 {Family: FamilyPRNG},
	// Still compound in the pack: splitting it needs per-algorithm-per-language
	// rules, because a rule naming an algorithm in a string cannot span
	// languages. It normalises to the family with no parameter — which is
	// exactly the coarse component the merge rule was written for.
	"des/3des/rc4": {Family: FamilyLegacySym},
	"md5/sha-1":    {Family: FamilyMD5},

	// CAMP wire names. These DO name a specific group, so they carry it.
	"x25519mlkem768":        {Family: FamilyHybridKEM, Parameter: "x25519mlkem768"},
	"secp256r1mlkem768":     {Family: FamilyHybridKEM, Parameter: "secp256r1mlkem768"},
	"secp384r1mlkem1024":    {Family: FamilyHybridKEM, Parameter: "secp384r1mlkem1024"},
	"x25519kyber768draft00": {Family: FamilyHybridKEM, Parameter: "x25519kyber768draft00"},
	"p256kyber768draft00":   {Family: FamilyHybridKEM, Parameter: "p256kyber768draft00"},
	"mlkem512":              {Family: FamilyMLKEM, Parameter: "mlkem512"},
	"mlkem768":              {Family: FamilyMLKEM, Parameter: "mlkem768"},
	"mlkem1024":             {Family: FamilyMLKEM, Parameter: "mlkem1024"},
	"secp256r1":             {Family: FamilyEC, Parameter: "secp256r1"},
	"secp384r1":             {Family: FamilyEC, Parameter: "secp384r1"},
	"secp521r1":             {Family: FamilyEC, Parameter: "secp521r1"},
	// The other names for the NIST curves (OpenSSL, NIST, SSH). BOMRef gives them
	// all the secp name; see canonicalCurve.
	"prime256v1": {Family: FamilyEC, Parameter: "secp256r1"},
	"p256":       {Family: FamilyEC, Parameter: "secp256r1"},
	"p384":       {Family: FamilyEC, Parameter: "secp384r1"},
	"p521":       {Family: FamilyEC, Parameter: "secp521r1"},
	"nistp256":   {Family: FamilyEC, Parameter: "secp256r1"},
	"nistp384":   {Family: FamilyEC, Parameter: "secp384r1"},
	"nistp521":   {Family: FamilyEC, Parameter: "secp521r1"},
	"x25519":     {Family: FamilyEC, Parameter: "x25519"},
	"x448":       {Family: FamilyEC, Parameter: "x448"},
	// EdDSA. "Ed25519-256" is how CAMP's scanner has always named the key
	// (Go's name and its size), so it is listed rather than split, which would
	// make it "ec/256" and merge it with P-256.
	"ed25519":     {Family: FamilyEC, Parameter: "ed25519"},
	"ed25519-256": {Family: FamilyEC, Parameter: "ed25519"},
	"ed448":       {Family: FamilyEC, Parameter: "ed448"},
	"ffdhe2048":   {Family: FamilyDH, Parameter: "ffdhe2048"},
	"ffdhe3072":   {Family: FamilyDH, Parameter: "ffdhe3072"},
	"ffdhe4096":   {Family: FamilyDH, Parameter: "ffdhe4096"},
	"3des":        {Family: FamilyLegacySym, Parameter: "3des"},
	"des":         {Family: FamilyLegacySym, Parameter: "des"},
	"rc4":         {Family: FamilyLegacySym, Parameter: "rc4"},
	"rc2":         {Family: FamilyLegacySym, Parameter: "rc2"},
	"blowfish":    {Family: FamilyLegacySym, Parameter: "blowfish"},
	"aes":         {Family: FamilyAES},
	"sha-256":     {Family: FamilySHA2, Parameter: "sha256"},
	"sha256":      {Family: FamilySHA2, Parameter: "sha256"},
	"sha-384":     {Family: FamilySHA2, Parameter: "sha384"},
	"sha384":      {Family: FamilySHA2, Parameter: "sha384"},
	"sha-512":     {Family: FamilySHA2, Parameter: "sha512"},
	"sha512":      {Family: FamilySHA2, Parameter: "sha512"},

	// The POST-QUANTUM standards, under their own spellings.
	//
	// These were missing, and their absence was quietly load-bearing. CAMP-6's
	// signature rollup detects ML-DSA with SQL LIKE '%ML-DSA%' because the
	// vocabulary could not answer, and a vendor's own CBOM names algorithms the
	// way FIPS 203/204/205 do — so the one place a supplier states what its
	// product supports produced FamilyUnknown for every entry.
	//
	// Two vocabularies wearing a different hat is what this map exists to
	// prevent. It was happening here.
	"ml-kem":      {Family: FamilyMLKEM},
	"ml-kem-512":  {Family: FamilyMLKEM, Parameter: "mlkem512"},
	"ml-kem-768":  {Family: FamilyMLKEM, Parameter: "mlkem768"},
	"ml-kem-1024": {Family: FamilyMLKEM, Parameter: "mlkem1024"},
	"ml-dsa":      {Family: FamilyMLDSA},
	"ml-dsa-44":   {Family: FamilyMLDSA, Parameter: "mldsa44"},
	"ml-dsa-65":   {Family: FamilyMLDSA, Parameter: "mldsa65"},
	"ml-dsa-87":   {Family: FamilyMLDSA, Parameter: "mldsa87"},
	// FIPS 205 names twelve parameter sets and they are ENUMERATED rather than
	// matched by prefix. A prefix rule would claim to recognise anything
	// beginning "slh-dsa", including a spelling nobody standardised, and this
	// map's whole job is to refuse to guess.
	"slh-dsa":            {Family: FamilySLHDSA},
	"slh-dsa-sha2-128s":  {Family: FamilySLHDSA, Parameter: "slhdsasha2128s"},
	"slh-dsa-sha2-128f":  {Family: FamilySLHDSA, Parameter: "slhdsasha2128f"},
	"slh-dsa-sha2-192s":  {Family: FamilySLHDSA, Parameter: "slhdsasha2192s"},
	"slh-dsa-sha2-192f":  {Family: FamilySLHDSA, Parameter: "slhdsasha2192f"},
	"slh-dsa-sha2-256s":  {Family: FamilySLHDSA, Parameter: "slhdsasha2256s"},
	"slh-dsa-sha2-256f":  {Family: FamilySLHDSA, Parameter: "slhdsasha2256f"},
	"slh-dsa-shake-128s": {Family: FamilySLHDSA, Parameter: "slhdsashake128s"},
	"slh-dsa-shake-128f": {Family: FamilySLHDSA, Parameter: "slhdsashake128f"},
	"slh-dsa-shake-192s": {Family: FamilySLHDSA, Parameter: "slhdsashake192s"},
	"slh-dsa-shake-192f": {Family: FamilySLHDSA, Parameter: "slhdsashake192f"},
	"slh-dsa-shake-256s": {Family: FamilySLHDSA, Parameter: "slhdsashake256s"},
	"slh-dsa-shake-256f": {Family: FamilySLHDSA, Parameter: "slhdsashake256f"},

	// Composite signatures, RFC 10073: the algorithm names without "id-".
	"mldsa44-rsa2048-pss-sha256":           {Family: FamilyHybridSig, Parameter: "mldsa44rsa2048psssha256"},
	"mldsa44-rsa2048-pkcs15-sha256":        {Family: FamilyHybridSig, Parameter: "mldsa44rsa2048pkcs15sha256"},
	"mldsa44-ed25519-sha512":               {Family: FamilyHybridSig, Parameter: "mldsa44ed25519sha512"},
	"mldsa44-ecdsa-p256-sha256":            {Family: FamilyHybridSig, Parameter: "mldsa44ecdsap256sha256"},
	"mldsa65-rsa3072-pss-sha512":           {Family: FamilyHybridSig, Parameter: "mldsa65rsa3072psssha512"},
	"mldsa65-rsa3072-pkcs15-sha512":        {Family: FamilyHybridSig, Parameter: "mldsa65rsa3072pkcs15sha512"},
	"mldsa65-rsa4096-pss-sha512":           {Family: FamilyHybridSig, Parameter: "mldsa65rsa4096psssha512"},
	"mldsa65-rsa4096-pkcs15-sha512":        {Family: FamilyHybridSig, Parameter: "mldsa65rsa4096pkcs15sha512"},
	"mldsa65-ecdsa-p256-sha512":            {Family: FamilyHybridSig, Parameter: "mldsa65ecdsap256sha512"},
	"mldsa65-ecdsa-p384-sha512":            {Family: FamilyHybridSig, Parameter: "mldsa65ecdsap384sha512"},
	"mldsa65-ecdsa-brainpoolp256r1-sha512": {Family: FamilyHybridSig, Parameter: "mldsa65ecdsabrainpoolp256r1sha512"},
	"mldsa65-ed25519-sha512":               {Family: FamilyHybridSig, Parameter: "mldsa65ed25519sha512"},
	"mldsa87-ecdsa-p384-sha512":            {Family: FamilyHybridSig, Parameter: "mldsa87ecdsap384sha512"},
	"mldsa87-ecdsa-brainpoolp384r1-sha512": {Family: FamilyHybridSig, Parameter: "mldsa87ecdsabrainpoolp384r1sha512"},
	"mldsa87-ed448-shake256":               {Family: FamilyHybridSig, Parameter: "mldsa87ed448shake256"},
	"mldsa87-rsa3072-pss-sha512":           {Family: FamilyHybridSig, Parameter: "mldsa87rsa3072psssha512"},
	"mldsa87-rsa4096-pss-sha512":           {Family: FamilyHybridSig, Parameter: "mldsa87rsa4096psssha512"},
	"mldsa87-ecdsa-p521-sha512":            {Family: FamilyHybridSig, Parameter: "mldsa87ecdsap521sha512"},

	// Composite signatures, by the oqs-provider names PKI generated them under
	// before RFC 10073. Same family: a pre-standard hybrid is still a hybrid.
	"p256_mldsa44": {Family: FamilyHybridSig, Parameter: "p256mldsa44"},
	"p384_mldsa65": {Family: FamilyHybridSig, Parameter: "p384mldsa65"},
	"p521_mldsa87": {Family: FamilyHybridSig, Parameter: "p521mldsa87"},
}

// squashed indexes every entry with its separators removed, so one spelling of a
// name finds the other. Built once, from native, so there is exactly one place
// an algorithm is declared.
//
// It is a FALLBACK, tried only after an exact miss. Separator-insensitive
// matching is a convenience for spellings of the SAME name — "ML-KEM-768" and
// "mlkem768" — and letting it run first would let it decide cases the exact map
// already answers.
var squashed = func() map[string]Algorithm {
	m := make(map[string]Algorithm, len(native))
	for k, v := range native {
		s := stripSeparators(k)
		// A collision would mean two DIFFERENT algorithms whose names differ
		// only in punctuation. There are none today; if one ever appears, the
		// exact map still answers it and the fallback simply declines.
		if _, clash := m[s]; clash {
			continue
		}
		m[s] = v
	}
	return m
}()

func stripSeparators(s string) string {
	return strings.NewReplacer("-", "", "_", "", " ", "", ".", "").Replace(s)
}

// Normalise maps a product's own name for an algorithm onto a shared identity.
//
// The second return says whether the name was recognised. An unrecognised name
// is NOT an error: it becomes FamilyUnknown carrying its native spelling, so it
// still appears in the inventory. Dropping it would be the one outcome worse
// than not classifying it.
func Normalise(nativeName string) (Algorithm, bool) {
	key := strings.ToLower(strings.TrimSpace(nativeName))
	if key == "" {
		return Algorithm{Family: FamilyUnknown}, false
	}
	a, ok := native[key]
	if !ok {
		// One name, several spellings. FIPS 203 writes ML-KEM-768 and CAMP's
		// wire names write mlkem768; both are the same algorithm and neither is
		// wrong.
		a, ok = squashed[stripSeparators(key)]
	}
	if !ok {
		// FAMILY PLUS PARAMETER, which is the form a network probe produces.
		//
		// CAMP writes fmt.Sprintf("%s-%d", algorithm, bits) — RSA-3072,
		// ECDSA-256 — so every key it discovers missed the table entirely and
		// landed as crypto/unknown/rsa3072 with no risk assessment. An agency's
		// CBOM said "unclassified" for an estate of plain RSA.
		//
		// It also broke the merge this package exists for: QryptoScan emits the
		// coarse crypto/rsa and CAMP emitted crypto/unknown/rsa3072, which are
		// not the same component and never would be. Split, they become
		// crypto/rsa and crypto/rsa/3072 — related, distinct, and exactly the
		// coarse-versus-specific pair BOMRef is designed around.
		//
		// Only a HEAD THAT IS ITSELF A KNOWN ALGORITHM is accepted, so this
		// cannot invent a family out of an unrecognised name: RSA-3072 splits,
		// PLUMBUS-9 does not.
		if split, param, found := splitParameter(key); found {
			split.Native, split.Parameter = nativeName, param
			return split, true
		}
		return Algorithm{Family: FamilyUnknown, Native: nativeName}, false
	}
	a.Native = nativeName
	return a, true
}

// splittable names the families whose parameter is a FREE VALUE — a modulus
// size, a curve — so any tail is plausible and the family is what carries the
// risk. RSA-3072 and RSA-4096 are both RSA, and a size this package has not seen
// is still RSA.
//
// The post-quantum families are deliberately absent. Their parameter sets are
// ENUMERATED by the standards, so a tail that is not one of them is not a
// variant — it is a name for something that does not exist, and accepting it
// would put a fabricated algorithm in a document an agency submits.
// SLH-DSA-SHA3-128s is the case that proves it: FIPS 205 defines SHA2 and SHAKE
// variants and no SHA3 one, and splitting would have reported it as a genuine
// SLH-DSA parameter set. Those names must match the table exactly.
var splittable = map[Family]bool{
	FamilyRSA: true, FamilyEC: true, FamilyDH: true, FamilyDSA: true,
	FamilyAES: true, FamilySHA2: true, FamilyLegacySym: true,
}

// splitParameter tries "<known algorithm><sep><parameter>".
//
// Separators only — it never splits inside a word, so ED25519 stays whole while
// Ed25519-256 does not. The parameter keeps the caller's spelling; BOMRef
// normalises it.
func splitParameter(key string) (Algorithm, string, bool) {
	for i := len(key) - 1; i > 0; i-- {
		switch key[i] {
		case '-', '_', ' ', '/', '.':
		default:
			continue
		}
		head, tail := key[:i], key[i+1:]
		if tail == "" {
			continue
		}
		a, ok := native[head]
		if !ok {
			a, ok = squashed[stripSeparators(head)]
		}
		if ok && splittable[a.Family] {
			return a, tail, true
		}
	}
	return Algorithm{}, "", false
}

// Assess returns the risk for an algorithm, and whether that answer rests on
// knowledge rather than on the memo's default.
//
// The default is FAIL-CLOSED, because the memo asks for it: agencies are
// "encouraged to treat as quantum-vulnerable any asymmetric algorithm that is
// not definitively known to be quantum-resistant". An unrecognised name could
// be anything, so it is treated as broken — and the false return is how a
// caller knows to record that finding at low confidence rather than beside a
// known break.
func Assess(a Algorithm) (Risk, bool) {
	if p, ok := profiles[a.Family]; ok {
		return p.Risk, true
	}
	return QuantumBroken, false
}
