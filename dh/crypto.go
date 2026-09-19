package dh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Device info decryption constants
var (
	deviceInfoKey = []byte("kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf")
	deviceInfoIV  = []byte("MydvJw*Iw1w&i^kk")

	// Default IV for IP address encryption/decryption
	ipEncryptIV = []byte("2z52*lk9o6HRyJrf")
)

// DeviceInfo contains the decrypted device information
type DeviceInfo struct {
	HTTPPort    int    `json:"httpport"`
	PrivPort    int    `json:"privport"`
	RandSalt    string `json:"randsalt"`
	RTSPPort    int    `json:"rtspport"`
	TLSPrivPort int    `json:"tlsprivport"`
}

// DecryptDeviceInfo decrypts the base64-encoded Info field from /info/device response
func DecryptDeviceInfo(infoB64 string) (*DeviceInfo, error) {
	cipherText, err := base64.StdEncoding.DecodeString(infoB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode device info: %w", err)
	}

	block, err := aes.NewCipher(deviceInfoKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	stream := cipher.NewOFB(block, deviceInfoIV)
	plainText := make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)

	var info DeviceInfo
	if err := json.Unmarshal(plainText, &info); err != nil {
		return nil, fmt.Errorf("failed to parse device info JSON: %w", err)
	}

	return &info, nil
}

// GetDeviceKey computes the device authentication key from username, password and randsalt
// key = MD5("username:Login to randsalt:password") as uppercase hex
func GetDeviceKey(username, password, randsalt string) []byte {
	raw := fmt.Sprintf("%s:Login to %s:%s", username, randsalt, password)
	hash := md5.Sum([]byte(raw))
	key := fmt.Sprintf("%X", hash)
	return []byte(key)
}

// GetDeviceNonce generates a random nonce for device authentication
func GetDeviceNonce() int {
	b := RandomBytes(4)
	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
}

// EncryptAddr encrypts a local address using PBKDF2 + AES-OFB
func EncryptAddr(key []byte, nonce int, data string) (string, error) {
	salt := []byte(fmt.Sprintf("%d", nonce))
	dk := pbkdf2SHA256(key, salt, 20000, 32)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	stream := cipher.NewOFB(block, ipEncryptIV)
	cipherText := make([]byte, len(data))
	stream.XORKeyStream(cipherText, []byte(data))

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptAddr decrypts an address using PBKDF2 + AES-OFB
func DecryptAddr(key []byte, nonce int, data string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	salt := []byte(fmt.Sprintf("%d", nonce))
	dk := pbkdf2SHA256(key, salt, 20000, 32)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}

	stream := cipher.NewOFB(block, ipEncryptIV)
	plainText := make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)

	return string(plainText), nil
}

// GetDeviceAuth generates the device authentication XML fragment
func GetDeviceAuth(username string, key []byte, nonce int, randsalt string, payload string) string {
	curdate := time.Now().Unix()

	message := fmt.Sprintf("%d%d%s", nonce, curdate, payload)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	auth := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("<CreateDate>%d</CreateDate>"+
		"<DevAuth>%s</DevAuth>"+
		"<Nonce>%d</Nonce>"+
		"<RandSalt>%s</RandSalt>"+
		"<UserName>%s</UserName>",
		curdate, auth, nonce, randsalt, username)
}

// pbkdf2SHA256 implements PBKDF2 with SHA-256
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	mac := hmac.New(sha256.New, password)
	hashLen := mac.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)

	for block := 1; block <= numBlocks; block++ {
		mac.Reset()
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}

		dk = append(dk, t...)
	}

	return dk[:keyLen]
}
