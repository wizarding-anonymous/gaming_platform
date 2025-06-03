// File: internal/utils/crypto/crypto.go

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Encrypter представляет интерфейс для шифрования и дешифрования данных
type Encrypter struct {
	key []byte
}

// NewEncrypter создает новый экземпляр шифровальщика
func NewEncrypter(key []byte) (*Encrypter, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("ключ шифрования должен быть длиной 16, 24 или 32 байта")
	}
	return &Encrypter{key: key}, nil
}

// Encrypt шифрует данные с использованием AES-GCM
func (e *Encrypter) Encrypt(plaintext []byte) (string, error) {
	// Создаем новый шифр AES
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("ошибка создания шифра AES: %w", err)
	}

	// Создаем новый GCM режим
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("ошибка создания GCM режима: %w", err)
	}

	// Создаем nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("ошибка создания nonce: %w", err)
	}

	// Шифруем данные
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	// Кодируем в base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt дешифрует данные с использованием AES-GCM
func (e *Encrypter) Decrypt(encryptedText string) ([]byte, error) {
	// Декодируем из base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования base64: %w", err)
	}

	// Создаем новый шифр AES
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания шифра AES: %w", err)
	}

	// Создаем новый GCM режим
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM режима: %w", err)
	}

	// Проверяем, что ciphertext достаточно длинный
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("шифротекст слишком короткий")
	}

	// Извлекаем nonce и шифротекст
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Дешифруем данные
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка дешифрования: %w", err)
	}

	return plaintext, nil
}

// EncryptString шифрует строку с использованием AES-GCM
func (e *Encrypter) EncryptString(plaintext string) (string, error) {
	return e.Encrypt([]byte(plaintext))
}

// DecryptString дешифрует строку с использованием AES-GCM
func (e *Encrypter) DecryptString(encryptedText string) (string, error) {
	plaintext, err := e.Decrypt(encryptedText)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// GenerateKey генерирует случайный ключ шифрования указанной длины
func GenerateKey(keySize int) ([]byte, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, errors.New("размер ключа должен быть 16, 24 или 32 байта")
	}
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации ключа: %w", err)
	}
	return key, nil
}

// GenerateKeyString генерирует случайный ключ шифрования указанной длины и возвращает его в виде строки base64
func GenerateKeyString(keySize int) (string, error) {
	key, err := GenerateKey(keySize)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// ParseKeyString преобразует строку base64 в ключ шифрования
func ParseKeyString(keyString string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(keyString)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования ключа: %w", err)
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("размер ключа должен быть 16, 24 или 32 байта")
	}
	return key, nil
}
