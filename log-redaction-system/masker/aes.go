// Package masker cung cap AES-128 cho che giau va giai ma du lieu.
package masker

import (
	"bytes"
	"encoding/hex"
)

var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}
var rcon = []byte{0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36}
// xtime nhan mot byte trong GF(2^8) theo quy tac AES.


func xtime(a byte) byte {
	if a&0x80 != 0 {
		return (a << 1) ^ 0x1B
	}
	return a << 1
}

// keyExpansion mo rong khoa 16 byte thanh 11 round keys.

func keyExpansion(key []byte) [][]byte {
	w := make([]byte, 176)
	copy(w, key)

	for i := 4; i < 44; i++ {
		temp := make([]byte, 4)
		copy(temp, w[(i-1)*4:i*4])

		if i%4 == 0 {
			t := temp[0]
			temp[0] = sbox[temp[1]] ^ rcon[i/4]
			temp[1] = sbox[temp[2]]
			temp[2] = sbox[temp[3]]
			temp[3] = sbox[t]
		}
		for j := 0; j < 4; j++ {
			w[i*4+j] = w[(i-4)*4+j] ^ temp[j]
		}
	}

	roundKeys := make([][]byte, 11)
	for i := 0; i < 11; i++ {
		roundKeys[i] = w[i*16 : (i+1)*16]
	}
	return roundKeys
}

// mixColumns ap dung phep MixColumns cho trang thai 16 byte.

func mixColumns(s []byte) {
	for i := 0; i < 16; i += 4 {
		c := make([]byte, 4)
		copy(c, s[i:i+4])

		s[i] = xtime(c[0]) ^ (xtime(c[1]) ^ c[1]) ^ c[2] ^ c[3]
		s[i+1] = c[0] ^ xtime(c[1]) ^ (xtime(c[2]) ^ c[2]) ^ c[3]
		s[i+2] = c[0] ^ c[1] ^ xtime(c[2]) ^ (xtime(c[3]) ^ c[3])
		s[i+3] = (xtime(c[0]) ^ c[0]) ^ c[1] ^ c[2] ^ xtime(c[3])
	}
}

// aesEncryptBlock ma hoa mot khoi 16 byte theo AES-128.

func aesEncryptBlock(block []byte, roundKeys [][]byte) []byte {
	state := make([]byte, 16)
	copy(state, block)
	for i := 0; i < 16; i++ {
		state[i] ^= roundKeys[0][i]
	}
	for r := 1; r < 10; r++ {
		for i := 0; i < 16; i++ {
			state[i] = sbox[state[i]]
		}
		state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
		state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
		state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
		mixColumns(state)
		for i := 0; i < 16; i++ {
			state[i] ^= roundKeys[r][i]
		}
	}
	for i := 0; i < 16; i++ {
		state[i] = sbox[state[i]]
	}
	state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
	state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
	state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
	for i := 0; i < 16; i++ {
		state[i] ^= roundKeys[10][i]
	}

	return state
}

// MaskDataWithAES ma hoa chuoi bang AES-128 va tra ve chuoi hex.

func MaskDataWithAES(rawData string, secretKey string) string {
	keyBytes := []byte(secretKey)
	if len(keyBytes) < 16 {
		padding := bytes.Repeat([]byte{0}, 16-len(keyBytes))
		keyBytes = append(keyBytes, padding...)
	} else {
		keyBytes = keyBytes[:16]
	}

	dataBytes := []byte(rawData)
	padLen := 16 - (len(dataBytes) % 16)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	dataToEncrypt := append(dataBytes, padding...)

	roundKeys := keyExpansion(keyBytes)
	var encrypted []byte
	for i := 0; i < len(dataToEncrypt); i += 16 {
		block := dataToEncrypt[i : i+16]
		encryptedBlock := aesEncryptBlock(block, roundKeys)
		encrypted = append(encrypted, encryptedBlock...)
	}
	return hex.EncodeToString(encrypted)
}

var invSbox [256]byte

// init khoi tao bang inverse S-Box cho giai ma.
func init() {
	for i, v := range sbox {
		invSbox[v] = byte(i)
	}
}

// mulGf nhan hai byte trong GF(2^8).

func mulGf(a, b byte) byte {
	var res byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			res ^= a
		}
		a = xtime(a)
		b >>= 1
	}
	return res
}

// invMixColumns ap dung phep InvMixColumns cho trang thai 16 byte.


func invMixColumns(s []byte) {
	for i := 0; i < 16; i += 4 {
		c := make([]byte, 4)
		copy(c, s[i:i+4])
		s[i] = mulGf(c[0], 0x0e) ^ mulGf(c[1], 0x0b) ^ mulGf(c[2], 0x0d) ^ mulGf(c[3], 0x09)
		s[i+1] = mulGf(c[0], 0x09) ^ mulGf(c[1], 0x0e) ^ mulGf(c[2], 0x0b) ^ mulGf(c[3], 0x0d)
		s[i+2] = mulGf(c[0], 0x0d) ^ mulGf(c[1], 0x09) ^ mulGf(c[2], 0x0e) ^ mulGf(c[3], 0x0b)
		s[i+3] = mulGf(c[0], 0x0b) ^ mulGf(c[1], 0x0d) ^ mulGf(c[2], 0x09) ^ mulGf(c[3], 0x0e)
	}
}

// aesDecryptBlock giai ma mot khoi 16 byte theo AES-128.

func aesDecryptBlock(block []byte, roundKeys [][]byte) []byte {
	state := make([]byte, 16)
	copy(state, block)

	for i := 0; i < 16; i++ {
		state[i] ^= roundKeys[10][i]
	}

	for r := 9; r > 0; r-- {
		state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
		state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
		state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
		for i := 0; i < 16; i++ {
			state[i] = invSbox[state[i]]
		}
		for i := 0; i < 16; i++ {
			state[i] ^= roundKeys[r][i]
		}
		invMixColumns(state)
	}
	state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
	state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
	state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
	for i := 0; i < 16; i++ {
		state[i] = invSbox[state[i]]
	}
	for i := 0; i < 16; i++ {
		state[i] ^= roundKeys[0][i]
	}

	return state
}

// DecryptDataWithAES giai ma chuoi hex bang AES-128 va tra ve chuoi goc.
func DecryptDataWithAES(hexStr string, secretKey string) string {
	keyBytes := []byte(secretKey)
	if len(keyBytes) < 16 {
		padding := bytes.Repeat([]byte{0}, 16-len(keyBytes))
		keyBytes = append(keyBytes, padding...)
	} else {
		keyBytes = keyBytes[:16]
	}

	encrypted, err := hex.DecodeString(hexStr)
	if err != nil || len(encrypted)%16 != 0 {
		return hexStr
	}

	roundKeys := keyExpansion(keyBytes)
	var decrypted []byte

	for i := 0; i < len(encrypted); i += 16 {
		block := encrypted[i : i+16]
		decryptedBlock := aesDecryptBlock(block, roundKeys)
		decrypted = append(decrypted, decryptedBlock...)
	}
	if len(decrypted) > 0 {
		padLen := int(decrypted[len(decrypted)-1])
		if padLen > 0 && padLen <= 16 {
			decrypted = decrypted[:len(decrypted)-padLen]
		}
	}

	return string(decrypted)
}
