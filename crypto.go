package envx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// encryptedPrefix identifies ML-KEM-768 + AES-256-GCM sealed values (FIPS 203 ML-KEM).
const encryptedPrefix = "encrypted_pqc:"

const (
	// pqcWireVersionLegacy marks payloads sealed before context binding existed. They
	// carry no AEAD additional authenticated data and remain decryptable so existing
	// encrypted files keep working; re-running `envx encrypt` upgrades them.
	pqcWireVersionLegacy byte = 1
	// pqcWireVersion is the current wire version. Its AES-GCM tag covers the
	// EncryptionContext (see EncryptionContext.aad) as additional authenticated data,
	// binding the ciphertext to the variable name and env-file public-key var it was
	// sealed for.
	pqcWireVersion   byte = 2
	kemCiphertextLen int  = 1088 // ML-KEM-768
	aesNonceLen      int  = 12   // GCM standard nonce
)

// aadDomain is a domain-separation tag prepended to every AAD so the additional
// authenticated data for envx ciphertext can never collide with unrelated bytes.
const aadDomain = "envx-pqc-aad-v1"

// EncryptionContext binds a sealed value to the position it occupies in a dotenv
// file. It is supplied to the AEAD as additional authenticated data (AAD): the data
// is authenticated but not encrypted, so decryption fails unless the same context is
// presented. This prevents a ciphertext from being silently moved to a different
// variable name, or copied into a different env file (which uses a different
// DOTENV_PUBLIC_KEY_* name), without detection.
type EncryptionContext struct {
	// VarName is the dotenv variable the value is assigned to (e.g. "DATABASE_URL").
	VarName string
	// PublicKeyVar is the env-file-specific public-key variable name returned by
	// PublicKeyVarForEnvFile (e.g. "DOTENV_PUBLIC_KEY" or "DOTENV_PUBLIC_KEY_PRODUCTION").
	PublicKeyVar string
}

// aad returns the additional authenticated data for the context: a domain-separated,
// length-prefixed encoding of (PublicKeyVar, VarName). Length-prefixing makes the
// encoding unambiguous, so distinct field combinations can never produce the same
// bytes (e.g. {"A", "BC"} and {"AB", "C"} stay distinct).
func (c EncryptionContext) aad() []byte {
	var b []byte
	b = appendLengthPrefixed(b, []byte(aadDomain))
	b = appendLengthPrefixed(b, []byte(c.PublicKeyVar))
	b = appendLengthPrefixed(b, []byte(c.VarName))
	return b
}

// contextForFileVar builds the EncryptionContext for variable varName in envFile,
// deriving the env-file-specific public-key variable name. Encryption and decryption
// of a file's values funnel through this so both sides agree on the binding.
func contextForFileVar(envFile, varName string) EncryptionContext {
	return EncryptionContext{
		VarName:      varName,
		PublicKeyVar: PublicKeyVarForEnvFile(envFile),
	}
}

func appendLengthPrefixed(dst, field []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(field)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, field...)
}

var (
	ErrMissingPrivateKey  = errors.New("missing DOTENV_PRIVATE_KEY (or .env.keys entry) for decrypting encrypted values")
	ErrInvalidCiphertext  = errors.New("invalid encrypted payload")
	ErrDecryptionFailed   = errors.New("failed to decrypt with provided private key(s)")
	ErrMissingPublicKey   = errors.New("missing DOTENV_PUBLIC_KEY for encryption")
	ErrInvalidPublicKey   = errors.New("invalid DOTENV_PUBLIC_KEY")
	ErrInvalidPrivateKey  = errors.New("invalid DOTENV_PRIVATE_KEY")
	ErrInvalidKeyMaterial = errors.New("invalid key material")
)

// DecryptIfEncrypted decrypts values of the form `encrypted_pqc:<base64>` using any of the provided
// private keys (base64-encoded 64-byte ML-KEM decapsulation seeds). If the value is not encrypted, it returns it unchanged.
//
// ctx supplies the additional authenticated data the value was sealed with (see
// EncryptionContext). For current (v2) ciphertexts, decryption fails unless ctx matches
// the context used at encryption time; legacy (v1) ciphertexts carry no AAD and ignore ctx.
func DecryptIfEncrypted(value string, privateKeysB64 []string, ctx EncryptionContext) (string, error) {
	if !strings.HasPrefix(value, encryptedPrefix) {
		return value, nil
	}
	if len(privateKeysB64) == 0 {
		return "", ErrMissingPrivateKey
	}

	payloadB64 := strings.TrimPrefix(value, encryptedPrefix)
	payload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", fmt.Errorf("%w: base64 decode: %v", ErrInvalidCiphertext, err)
	}

	var lastErr error
	for _, pkB64 := range privateKeysB64 {
		pkB64 = strings.TrimSpace(pkB64)
		if pkB64 == "" {
			continue
		}
		plain, err := decryptPQCPayload(payload, pkB64, ctx)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		return "", ErrInvalidPrivateKey
	}
	return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, lastErr)
}

// Encrypt encrypts a plaintext using the receiver's ML-KEM encapsulation key (base64, 1184 bytes raw).
// It returns a string of the form `encrypted_pqc:<base64>`.
//
// ctx binds the ciphertext to its dotenv variable name and the env file's public-key
// variable name via AEAD additional authenticated data; the same ctx must be supplied
// to DecryptIfEncrypted to recover the plaintext.
func Encrypt(plaintext string, publicKeyB64 string, ctx EncryptionContext) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	ek, err := mlkem.NewEncapsulationKey768(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	payload, err := encryptPQCPayload([]byte(plaintext), ek, ctx.aad())
	if err != nil {
		return "", err
	}
	return encryptedPrefix + base64.StdEncoding.EncodeToString(payload), nil
}

// isLegacyEncrypted reports whether value is an encrypted_pqc payload sealed with
// the pre-AAD wire version (v1). Non-encrypted or malformed/undecodable payloads
// return false, so callers leave them untouched rather than risk rewriting garbage.
func isLegacyEncrypted(value string) bool {
	if !strings.HasPrefix(value, encryptedPrefix) {
		return false
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, encryptedPrefix))
	if err != nil || len(payload) == 0 {
		return false
	}
	return payload[0] == pqcWireVersionLegacy
}

// GenerateKeypair returns (publicKeyBase64, privateKeyBase64) for ML-KEM-768.
func GenerateKeypair() (string, string, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return "", "", err
	}
	ek := dk.EncapsulationKey()
	pubB64 := base64.StdEncoding.EncodeToString(ek.Bytes())
	privB64 := base64.StdEncoding.EncodeToString(dk.Bytes())
	return pubB64, privB64, nil
}

func decryptPQCPayload(payload []byte, privateKeyB64 string, ctx EncryptionContext) (string, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKeyB64))
	if err != nil || len(seed) != 64 {
		return "", ErrInvalidPrivateKey
	}
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return "", ErrInvalidPrivateKey
	}

	minLen := 1 + kemCiphertextLen + aesNonceLen
	if len(payload) < minLen {
		return "", ErrInvalidCiphertext
	}
	version := payload[0]
	if version != pqcWireVersion && version != pqcWireVersionLegacy {
		return "", ErrInvalidCiphertext
	}

	kemCT := payload[1 : 1+kemCiphertextLen]
	nonce := payload[1+kemCiphertextLen : minLen]
	sealed := payload[minLen:]

	sharedKey, err := dk.Decapsulate(kemCT)
	if err != nil {
		return "", ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, aesNonceLen)
	if err != nil {
		return "", err
	}

	// Legacy payloads were sealed without AAD; current payloads bind the context.
	var aad []byte
	if version == pqcWireVersion {
		aad = ctx.aad()
	}

	plain, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return "", ErrInvalidCiphertext
	}
	return string(plain), nil
}

func encryptPQCPayload(plain []byte, ek *mlkem.EncapsulationKey768, aad []byte) ([]byte, error) {
	sharedKey, kemCT := ek.Encapsulate()
	if len(kemCT) != kemCiphertextLen {
		return nil, ErrInvalidKeyMaterial
	}

	nonce := make([]byte, aesNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, aesNonceLen)
	if err != nil {
		return nil, err
	}

	sealed := gcm.Seal(nil, nonce, plain, aad)

	out := make([]byte, 0, 1+len(kemCT)+len(nonce)+len(sealed))
	out = append(out, pqcWireVersion)
	out = append(out, kemCT...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}
