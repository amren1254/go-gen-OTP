package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
	"time"
)

type TOTP struct {
	SecretKey         string
	NoOfDigits        int
	RequiredAlgorithm string
	TimePeriod        int64
	UnixTime          int64
}

type HOTP struct {
	SecretKey  string
	NoOfDigits int
	Counter    int64
}

func (totp *TOTP) Generate() (string, error) {
	//var To int64 = 0
	var currentUnixTime int64
	if totp.SecretKey == "" {
		return "", fmt.Errorf("No Secret Key Provided")
	}
	if totp.NoOfDigits == 0 {
		totp.NoOfDigits = 6
	}
	if totp.RequiredAlgorithm == "" {
		totp.RequiredAlgorithm = "SHA1"
	}
	if totp.TimePeriod == 0 {
		totp.TimePeriod = 60
	}
	if totp.UnixTime != 0 {
		currentUnixTime = totp.UnixTime
	} else {
		currentUnixTime = time.Now().Unix()
	}
	currentUnixTime /= totp.TimePeriod
	return generateOTP(totp.SecretKey, currentUnixTime, totp.NoOfDigits, totp.RequiredAlgorithm)
}

func generateOTP(base32key string, counter int64, digits int, algo string) (string, error) {
	//var otp string
	var hmacinit hash.Hash
	counterbytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterbytes, uint64(counter))
	secretKey, err := base64.StdEncoding.DecodeString(base32key)
	if err != nil {
		return "", fmt.Errorf(err.Error(), base32key)
	}
	switch strings.ToUpper(algo) {
	case "SHA1":
		{
			hmacinit = hmac.New(sha1.New, secretKey)
		}
	case "SHA256":
		{
			hmacinit = hmac.New(sha256.New, secretKey)
		}
	case "SHA512":
		{
			hmacinit = hmac.New(sha512.New, secretKey)
		}
	default:
		{
			return "", fmt.Errorf("invalid algorithm provided")
		}
	}
	_, err = hmacinit.Write(counterbytes)
	if err != nil {
		return "", err
	}
	hash := hmacinit.Sum(nil)
	offset := hash[len(hash)-1] & 0xF
	hash = hash[offset : offset+4]
	hash[0] = hash[0] & 0x7F
	decimal := binary.BigEndian.Uint32((hash))
	otp := decimal % uint32(math.Pow10(digits))
	result := strconv.Itoa(int(otp))
	// for len(result) != digits {
	// 	result = strconv.Itoa("0") + digits
	// }
	return result, nil
}
func main() {
	totp := TOTP{
		SecretKey:         "testuser",
		NoOfDigits:        6,
		RequiredAlgorithm: "SHA512",
		TimePeriod:        5,
		UnixTime:          0,
	}
	otp, err := totp.Generate()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(otp)
}
