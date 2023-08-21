package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

// Define a secret key for signing and verifying the JWT
var jwtSecret = []byte("your-secret-key")

func main() {
	// Generate a new JWT
	tokenString, err := generateJWT()
	if err != nil {
		fmt.Println("Failed to generate JWT:", err)
		return
	}

	fmt.Println("Generated JWT:", tokenString)

	// Verify and parse the JWT
	token, err := verifyJWT(tokenString)
	if err != nil {
		fmt.Println("Failed to verify JWT:", err)
		return
	}

	// Extract claims from the JWT
	claims := token.Claims.(jwt.MapClaims)
	fmt.Println("Username:", claims["username"])
	fmt.Println("Expires At:", claims["exp"])
}

func generateJWT() (string, error) {
	// Create a new token object
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims (payload) for the token
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = "JohnDoe"
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expires in 24 hours

	// Sign the token with the secret key
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func verifyJWT(tokenString string) (*jwt.Token, error) {
	// Parse the token string
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// Return the secret key for validation
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	// Verify if the token is valid
	if !token.Valid {
		return nil, fmt.Errorf("Invalid token")
	}

	return token, nil
}
