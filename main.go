package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func generateKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, privateKey.PublicKey(), nil
}

func deriveRootKey(sharedSecret []byte) []byte {
	h := sha256.New()
	h.Write([]byte("root-key"))
	h.Write(sharedSecret)
	return h.Sum(nil)
}

func deriveChainKey(rootKey []byte) []byte {
	h := sha256.New()
	h.Write([]byte("chain-key"))
	h.Write(rootKey)
	return h.Sum(nil)
}

func deriveMessageKey(chainKey []byte) []byte {
	h := sha256.New()
	h.Write([]byte("message-key"))
	h.Write(chainKey)
	return h.Sum(nil)
}

func ratchetChainKey(chainKey []byte) []byte {
	h := sha256.New()
	h.Write([]byte("chain-ratchet"))
	h.Write(chainKey)
	return h.Sum(nil)
}

func encrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	return gcm.Open(
		nil,
		ciphertext[:nonceSize],
		ciphertext[nonceSize:],
		nil,
	)
}

func main() {

	// =========================================================
	// 1. INITIAL KEY EXCHANGE
	// =========================================================

	alicePrivate, alicePublic, _ := generateKeyPair()
	bobPrivate, bobPublic, _ := generateKeyPair()

	// Alice calculates shared secret
	aliceSharedSecret, _ := alicePrivate.ECDH(bobPublic)

	// Bob calculates shared secret
	bobSharedSecret, _ := bobPrivate.ECDH(alicePublic)

	fmt.Println(
		"Shared secrets equal:",
		string(aliceSharedSecret) == string(bobSharedSecret),
	)

	// =========================================================
	// 2. DERIVE ROOT KEY
	// =========================================================

	aliceRootKey := deriveRootKey(aliceSharedSecret)
	bobRootKey := deriveRootKey(bobSharedSecret)

	// =========================================================
	// 3. DERIVE CHAIN KEY
	// =========================================================

	aliceChainKey := deriveChainKey(aliceRootKey)
	bobChainKey := deriveChainKey(bobRootKey)

	// =========================================================
	// 4. MESSAGE 1
	// =========================================================

	aliceMessageKey := deriveMessageKey(aliceChainKey)

	ciphertext, _ := encrypt(
		aliceMessageKey,
		[]byte("Hello Bob!"),
	)

	// Bob independently derives same message key
	bobMessageKey := deriveMessageKey(bobChainKey)

	plaintext, _ := decrypt(
		bobMessageKey,
		ciphertext,
	)

	fmt.Println("Bob received:", string(plaintext))

	// =========================================================
	// 5. RATCHET
	// =========================================================

	aliceChainKey = ratchetChainKey(aliceChainKey)
	bobChainKey = ratchetChainKey(bobChainKey)

	// =========================================================
	// 6. MESSAGE 2
	// =========================================================

	aliceMessageKey = deriveMessageKey(aliceChainKey)

	ciphertext, _ = encrypt(
		aliceMessageKey,
		[]byte("How are you?"),
	)

	bobMessageKey = deriveMessageKey(bobChainKey)

	plaintext, _ = decrypt(
		bobMessageKey,
		ciphertext,
	)

	fmt.Println("Bob received:", string(plaintext))
}
