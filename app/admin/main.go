package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/pkg/errors"
)

/*
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private.pem -out public.pem
*/

func main() {
	//err := GenKey()
	err := GenToken()
	// err := ParseToken()

	if err != nil {
		log.Fatalln(err)
	}
}

// ParseToken hacks the code we need to parse and validate.
func ParseToken() error {
	tokenStr := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU0YmIyMTY1LTcxZTEtNDFhNi1hZjNlLTdkYTRhMGUxZTJjMSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NDU4MTE5MTQuNDQ2NDQ2MiwiaWF0IjoxNjE0Mjc1OTE0LjQ0NjQ1MywiaXNzIjoiaGFja2luZyBwcm9qZWN0Iiwic3ViIjoiMTIzNDU2IiwiUm9sZXMiOlsiQURNSU4iLCJPUEVSQVRPUiJdfQ.yyim-mK9brndDNXfzLMP5TyWCE-ZPE9H8A4XdJCpWpJwZnHf_eYMxSxIqVMCZfOJvzjyHNXUjFrSeqEgWtbsN5m1NrsJMyUGRS9Jkco8n4Br6QxLnsmAqCLVZs2yd_LClacmNOL9gSXqVnYfH52CoBzxdmNlChkt5dk2uOPkoFHTYPfJLx1-VmINjis9hTLYTiQUTu1etlEar1cwTqDJVBGomTxfnwGfp5b-zYY_k3J_uusUS9a85VYoTPgyYNY0-Y1JJm3D9qAbMP-aZAzS8yjuPDEmAOE4nLM5qdIZoBnJb_fz99kZtttNU1KPV5405GTK2maqTQa0vJo5gN6E0A"
	privateKeyFile := "private.pem"
	algorithm := "RS256"

	privatePEM, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return errors.Wrap(err, "reading PEM private key file")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privatePEM)
	if err != nil {
		return errors.Wrap(err, "parsing PEM into private key")
	}

	// Create the token parser to use. The algorithm used to sign the JWT must be
	// validated to avoid a critical vulnerability:
	// https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
	parser := jwt.NewParser(jwt.WithValidMethods([]string{algorithm}), jwt.WithAudience("student"))

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	}

	var claims struct {
		jwt.StandardClaims
		Roles []string
	}
	token, err := parser.ParseWithClaims(tokenStr, &claims, keyFunc)
	if err != nil {
		return errors.Wrap(err, "parsing token")
	}

	if !token.Valid {
		return errors.New("invalid token")
	}

	fmt.Print("\n\n")
	fmt.Println("Header:", token.Header)
	fmt.Println("Claims:", token.Claims)
	fmt.Print("\n\n")

	return nil
}

// GenToken generates a JWT for the specified user.
func GenToken() error {
	id := "123456"
	privateKeyFile := "private.pem"
	algorithm := "RS256"

	privatePEM, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return errors.Wrap(err, "reading PEM private key file")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privatePEM)
	if err != nil {
		return errors.Wrap(err, "parsing PEM into private key")
	}

	method := jwt.GetSigningMethod(algorithm)
	if method == nil {
		return errors.Errorf("unknown algorithm %v", algorithm)
	}

	// iss (issuer): Issuer of the JWT
	// sub (subject): Subject of the JWT (the user)
	// aud (audience): Recipient for which the JWT is intended
	// exp (expiration time): Time after which the JWT expires
	// nbf (not before time): Time before which the JWT must not be accepted for processing
	// iat (issued at time): Time at which the JWT was issued; can be used to determine age of the JWT
	// jti (JWT ID): Unique identifier; can be used to prevent the JWT from being replayed (allows a token to be used only once)
	claims := struct {
		jwt.StandardClaims
		Roles []string
	}{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "hacking project",
			Subject:   id,
			ExpiresAt: jwt.At(time.Now().Add(8760 * time.Hour)),
			IssuedAt:  jwt.Now(),
		},
		Roles: []string{"ADMIN", "OPERATOR"},
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = "54bb2165-71e1-41a6-af3e-7da4a0e1e2c1"

	str, err := token.SignedString(privateKey)
	if err != nil {
		return errors.Wrap(err, "signing token")
	}

	fmt.Print("\n\n")
	fmt.Println(str)
	fmt.Print("\n\n")

	return nil
}

// GenKey creates an x509 private/public key for auth tokens.
func GenKey() error {

	// Generate a new private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Create a file for the private key information in PEM form.
	privateFile, err := os.Create("private.pem")
	if err != nil {
		return errors.Wrap(err, "creating private file")
	}
	defer privateFile.Close()

	// Construct a PEM block for the private key.
	privateBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Write the private key to the private key file.
	if err := pem.Encode(privateFile, &privateBlock); err != nil {
		return errors.Wrap(err, "encoding to private file")
	}

	// Marshal the public key from the private key to PKIX.
	asn1Bytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return errors.Wrap(err, "marshaling public key")
	}

	// Create a file for the public key information in PEM form.
	publicFile, err := os.Create("public.pem")
	if err != nil {
		return errors.Wrap(err, "creating public file")
	}
	defer privateFile.Close()

	// Construct a PEM block for the public key.
	publicBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	// Write the public key to the private key file.
	if err := pem.Encode(publicFile, &publicBlock); err != nil {
		return errors.Wrap(err, "encoding to public file")
	}

	fmt.Println("private and public key files generated")
	return nil
}
