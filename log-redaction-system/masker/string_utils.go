// Package masker cung cap cac ham mask va giai ma IP/token.
package masker

import (
	"math/rand"
	"time"
	"unicode"
)

const SecretKey = "LogMaskingKey123"

// MaskIP ma hoa IP bang AES-128.
func MaskIP(ip string) string {
	return MaskDataWithAES(ip, SecretKey)
}

// MaskToken ma hoa token bang AES-128.
func MaskToken(token string) string {
	return MaskDataWithAES(token, SecretKey)
}

// DecryptIP giai ma IP tu chuoi hex AES.
func DecryptIP(encryptedIP string) string {
	return DecryptDataWithAES(encryptedIP, SecretKey)
}

// DecryptToken giai ma token tu chuoi hex AES.
func DecryptToken(encryptedToken string) string {
	return DecryptDataWithAES(encryptedToken, SecretKey)
}

// StaticMaskIP ap dung che mat na ky tu cho du lieu IP.
func StaticMaskIP(ip string) string {
	return CharacterMaskData(ip)
}

// StaticMaskToken ap dung che mat na ky tu cho token.
func StaticMaskToken(token string) string {
	return CharacterMaskData(token)
}

// CharacterMaskData che mat na ky tu theo nguyen tac giu ky tu nhan dien.
// - Neu chuoi co khoang trang: moi tu giu ky tu dau, phan con lai thay bang '*'.
// - Neu chuoi khong co khoang trang: giu ky tu dau/cuoi, phan giua thay bang '*'.


func CharacterMaskData(data string) string {
	runes := []rune(data)
	if len(runes) <= 1 {
		return data
	}

	hasSpace := false
	for _, r := range runes {
		if unicode.IsSpace(r) {
			hasSpace = true
			break
		}
	}

	if hasSpace {
		result := make([]rune, len(runes))
		inWord := false
		isFirstCharOfWord := false
		for i, r := range runes {
			if unicode.IsSpace(r) {
				result[i] = r
				inWord = false
				continue
			}

			if !inWord {
				inWord = true
				isFirstCharOfWord = true
			}

			if isFirstCharOfWord {
				result[i] = r
				isFirstCharOfWord = false
				continue
			}

			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				result[i] = '*'
			} else {
				result[i] = r
			}
		}
		return string(result)
	}

	if len(runes) == 2 {
		return string([]rune{runes[0], '*'})
	}

	result := make([]rune, len(runes))
	result[0] = runes[0]
	result[len(runes)-1] = runes[len(runes)-1]
	for i := 1; i < len(runes)-1; i++ {
		if unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i]) {
			result[i] = '*'
		} else {
			result[i] = runes[i]
		}
	}
	return string(result)
}

// RandomMaskData thay the du lieu bang du lieu gia co cung cau truc ky tu.

var letterCharset = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
var digitCharset = []rune("0123456789")
var noiseCharset = []rune("!@#$%^&*()-_=+[]{}:;,.?/")
var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func RandomMaskData(data string) string {
	runes := []rune(data)
	for i, r := range runes {
		switch {
		case unicode.IsLetter(r):
			runes[i] = letterCharset[seededRand.Intn(len(letterCharset))]
		case unicode.IsDigit(r):
			runes[i] = digitCharset[seededRand.Intn(len(digitCharset))]
		default:
			// Giu nguyen ky tu phan cach de bao toan cau truc.
		}
	}
	return string(runes)
}

// RandomMaskToken thay token bang du lieu gia sau khi rut gon de de hien thi.
func RandomMaskToken(token string) string {
	return RandomMaskData(token)
}

// ShuffleMaskData xao tron vi tri ky tu chu va so, giu nguyen dau cau truc ky tu dac biet.


func ShuffleMaskData(data string) string {
	runes := []rune(data)
	if len(runes) <= 1 {
		return data
	}

	letterPositions := make([]int, 0)
	letters := make([]rune, 0)
	digitPositions := make([]int, 0)
	digits := make([]rune, 0)

	for i, r := range runes {
		switch {
		case unicode.IsLetter(r):
			letterPositions = append(letterPositions, i)
			letters = append(letters, r)
		case unicode.IsDigit(r):
			digitPositions = append(digitPositions, i)
			digits = append(digits, r)
		}
	}
	seededRand.Shuffle(len(letters), func(i, j int) {
		letters[i], letters[j] = letters[j], letters[i]
	})
	seededRand.Shuffle(len(digits), func(i, j int) {
		digits[i], digits[j] = digits[j], digits[i]
	})
	for i, pos := range letterPositions {
		runes[pos] = letters[i]
	}
	for i, pos := range digitPositions {
		runes[pos] = digits[i]
	}
	return string(runes)
}

// ShuffleMaskToken xao tron token sau khi rut gon de de hien thi.
func ShuffleMaskToken(token string) string {
	return ShuffleMaskData(token)
}

// InsertMaskData them nhieu vao du lieu bang cach chen ky tu ngau nhien.
// Ky tu goc duoc giu nguyen thu tu, nhung du lieu dau ra dai hon va kho phan tich hon.

func InsertMaskData(data string) string {
	runes := []rune(data)
	if len(runes) == 0 {
		return data
	}

	result := make([]rune, 0, len(runes)*2)
	for _, r := range runes {
		result = append(result, r)
		if unicode.IsSpace(r) {
			continue
		}

		noiseLen := 1 + seededRand.Intn(2)
		for i := 0; i < noiseLen; i++ {
			result = append(result, noiseCharset[seededRand.Intn(len(noiseCharset))])
		}
	}
	return string(result)
}

// InsertMaskToken them nhieu vao token da rut gon de tranh dau ra qua dai.
func InsertMaskToken(token string) string {
	return InsertMaskData(token)
}
