package envx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// encryptedPrefix identifies ML-KEM-768 + AES-256-GCM sealed values (FIPS 203 ML-KEM).
const encryptedPrefix = "encrypted_pqc:"

const (
	pqcWireVersion   byte = 1
	kemCiphertextLen int  = 1088 // ML-KEM-768
	aesNonceLen      int  = 12   // GCM standard nonce
)

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
func DecryptIfEncrypted(value string, privateKeysB64 []string) (string, error) {
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
		plain, err := decryptPQCPayload(payload, pkB64)
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
func Encrypt(plaintext string, publicKeyB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	ek, err := mlkem.NewEncapsulationKey768(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	payload, err := encryptPQCPayload([]byte(plaintext), ek)
	if err != nil {
		return "", err
	}
	return encryptedPrefix + base64.StdEncoding.EncodeToString(payload), nil
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

func decryptPQCPayload(payload []byte, privateKeyB64 string) (string, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKeyB64))
	if err != nil || len(seed) != 64 {
		return "", ErrInvalidPrivateKey
	}
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return "", ErrInvalidPrivateKey
	}

	minLen := 1 + kemCiphertextLen + aesNonceLen
	if len(payload) < minLen || payload[0] != pqcWireVersion {
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

	plain, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", ErrInvalidCiphertext
	}
	return string(plain), nil
}

func encryptPQCPayload(plain []byte, ek *mlkem.EncapsulationKey768) ([]byte, error) {
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

	sealed := gcm.Seal(nil, nonce, plain, nil)

	out := make([]byte, 0, 1+len(kemCT)+len(nonce)+len(sealed))
	out = append(out, pqcWireVersion)
	out = append(out, kemCT...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}
