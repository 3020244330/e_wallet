package util

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"regexp"
)

func HashPassword(password string) string {
	passwordBytes := []byte(password)
	hashedPasswordBytes, err := bcrypt.GenerateFromPassword(passwordBytes, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(hashedPasswordBytes)
}

func CheckPasswordHash(password, passwordHash string) bool {
	passwordBytes := []byte(password)
	hashedPasswordBytes := []byte(passwordHash)
	err := bcrypt.CompareHashAndPassword(hashedPasswordBytes, passwordBytes)
	return err == nil
}

func GetClientIP(c *gin.Context) string {
	ip := c.ClientIP()
	return ip
}

func ValidatePassword(password string) error {
	if len(password) < 8 || len(password) > 20 {
		return errors.New("密码长度必须在8到20个字符之间")
	}

	upper := regexp.MustCompile(`[A-Z]`)
	lower := regexp.MustCompile(`[a-z]`)
	digit := regexp.MustCompile(`[0-9]`)
	special := regexp.MustCompile(`[^a-zA-Z0-9]`)

	types := 0
	if upper.MatchString(password) {
		types++
	}
	if lower.MatchString(password) {
		types++
	}
	if digit.MatchString(password) {
		types++
	}
	if special.MatchString(password) {
		types++
	}

	if types < 2 {
		return errors.New("密码必须包含大写字母、小写字母、数字和特殊字符中的至少两种")
	}

	return nil
}

func GenerateTempPassword() string {
	tempPassword := fmt.Sprintf("%06d", rand.Intn(1e6))
	return tempPassword
}

func GenerateRedPacketAmount() float64 {
	amount := rand.Float64() * 100
	return amount
}
