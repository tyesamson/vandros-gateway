package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
	minPassword  = 12
	maxPassword  = 128
)

var ErrPassword = errors.New("password must be 12 to 128 characters")

// HashPassword returns a PHC-encoded argon2id hash.
func HashPassword(password string) (string, error) {
	if err := checkPassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return formatHash(argonMemory, argonTime, argonThreads, salt, sum), nil
}

// VerifyPassword reports whether password matches an encoded argon2id hash.
// Parameters stored in the hash are honoured, with a cap so a row cannot
// force an unbounded allocation.
func VerifyPassword(password, encoded string) (bool, error) {
	if len(password) > maxPassword || strings.ContainsRune(password, 0) {
		return false, nil
	}
	memory, timeCost, threads, salt, want, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func checkPassword(password string) error {
	if len(password) < minPassword || len(password) > maxPassword || strings.ContainsRune(password, 0) {
		return ErrPassword
	}
	return nil
}

func formatHash(memory, timeCost uint32, threads uint8, salt, sum []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, timeCost, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	)
}

func parseHash(encoded string) (memory, timeCost uint32, threads uint8, salt, sum []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("unrecognised password hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return 0, 0, 0, nil, nil, errors.New("unrecognised password hash")
	}
	var threadsInt int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threadsInt); err != nil {
		return 0, 0, 0, nil, nil, errors.New("unrecognised password hash")
	}
	if memory < 8*1024 || memory > 256*1024 || timeCost < 1 || timeCost > 8 || threadsInt < 1 || threadsInt > 4 {
		return 0, 0, 0, nil, nil, errors.New("password hash parameters rejected")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return 0, 0, 0, nil, nil, errors.New("unrecognised password hash")
	}
	sum, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(sum) < 16 {
		return 0, 0, 0, nil, nil, errors.New("unrecognised password hash")
	}
	return memory, timeCost, uint8(threadsInt), salt, sum, nil
}
