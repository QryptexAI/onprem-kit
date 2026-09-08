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
	FamilyAES       Family = "aes"
	FamilySHA1      Family = "sha1"
	FamilySHA2      Family = "sha2"
	FamilyMD5       Family = "md5"
	FamilyLegacySym Family = "legacy-symmetric" // DES, 3DES, RC4, Blowfish
	FamilyPRNG      Family = "prng"
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

	FamilyAES:  {FamilyAES, NotApplicable, []Function{Encrypt, Decrypt}, "", nil, false},
	FamilySHA2: {FamilySHA2, NotApplicable, []Function{Digest}, "", nil, false},
	// Grover halves a hash's effective strength; SHA-1 was already too short.
	FamilySHA1: {FamilySHA1, QuantumWeakened, []Function{Digest}, "", nil, false},
	FamilyMD5:  {FamilyMD5, NotApplicable, []Function{Digest}, "", nil, false},
	FamilyLegacySym: {FamilyLegacySym, NotApplicable, []Function{Encrypt, Decrypt},
		"", nil, false},
	FamilyPRNG: {FamilyPRNG, NotApplicable, []Function{Other}, "", nil, false},
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
	"prng":    {Family: FamilyPRNG},
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
	"x25519":                {Family: FamilyEC, Parameter: "x25519"},
	"x448":                  {Family: FamilyEC, Parameter: "x448"},
	"ffdhe2048":             {Family: FamilyDH, Parameter: "ffdhe2048"},
	"ffdhe3072":             {Family: FamilyDH, Parameter: "ffdhe3072"},
	"ffdhe4096":             {Family: FamilyDH, Parameter: "ffdhe4096"},
	"3des":                  {Family: FamilyLegacySym, Parameter: "3des"},
	"des":                   {Family: FamilyLegacySym, Parameter: "des"},
	"rc4":                   {Family: FamilyLegacySym, Parameter: "rc4"},
	"rc2":                   {Family: FamilyLegacySym, Parameter: "rc2"},
	"blowfish":              {Family: FamilyLegacySym, Parameter: "blowfish"},
	"aes":                   {Family: FamilyAES},
	"sha-256":               {Family: FamilySHA2, Parameter: "sha256"},
	"sha256":                {Family: FamilySHA2, Parameter: "sha256"},
	"sha-384":               {Family: FamilySHA2, Parameter: "sha384"},
	"sha384":                {Family: FamilySHA2, Parameter: "sha384"},
	"sha-512":               {Family: FamilySHA2, Parameter: "sha512"},
	"sha512":                {Family: FamilySHA2, Parameter: "sha512"},
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
		return Algorithm{Family: FamilyUnknown, Native: nativeName}, false
	}
	a.Native = nativeName
	return a, true
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
