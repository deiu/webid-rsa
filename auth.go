package webidrsa

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	rdf "github.com/deiu/rdf2go"
)

var (
	tokens = map[string]*Token{}
	// token validity in minutes
	TokenDuration = 1
	DurationScale = time.Minute
)

type Token struct {
	Source string
	Nonce  string
	Valid  int64
}

// RSAAuthentication structure
type RSAAuthentication struct {
	Source, Nonce, Username string
}

// RSAAuthorization structure
type RSAAuthorization struct {
	Source, Username, Nonce, Signature string
}

// ParseRSAAuthorizationHeader parses an Authorization header into a local RSAAuthorization structure
func ParseRSAAuthorizationHeader(header string) (*RSAAuthorization, error) {
	auth := &RSAAuthorization{}

	if len(header) == 0 {
		return auth, errors.New("Cannot parse Authorization header: no header present")
	}

	opts := make(map[string]string)
	parts := strings.SplitN(header, " ", 2)
	if parts[0] != "WebID-RSA" {
		return auth, errors.New("Not a WebID-RSA authorization header. Got " + parts[0])
	}

	parts = strings.Split(parts[1], ",")

	for _, part := range parts {
		vals := strings.SplitN(strings.TrimSpace(part), "=", 2)
		key := vals[0]
		val := strings.Replace(vals[1], "\"", "", -1)
		opts[key] = val
	}

	auth = &RSAAuthorization{
		opts["source"],
		opts["username"],
		opts["nonce"],
		opts["sig"],
	}
	return auth, nil
}

// ParseRSAAuthenticateHeader parses an Authenticate header and returns an RSAAuthentication object
func ParseRSAAuthenticateHeader(header string) (*RSAAuthentication, error) {
	auth := &RSAAuthentication{}

	if len(header) == 0 {
		return auth, errors.New("Cannot parse WWW-Authenticate header: no header present")
	}

	opts := make(map[string]string)
	parts := strings.SplitN(header, " ", 2)
	if parts[0] != "WebID-RSA" {
		return auth, errors.New("Not a WebID-RSA authentication header. Got " + parts[0])
	}

	parts = strings.Split(parts[1], ",")

	for _, part := range parts {
		vals := strings.SplitN(strings.TrimSpace(part), "=", 2)
		key := vals[0]
		val := strings.Replace(vals[1], "\"", "", -1)
		opts[key] = val
	}

	auth = &RSAAuthentication{
		Source: opts["source"],
		Nonce:  opts["nonce"],
	}
	return auth, nil
}

// Authenticate authenticates a user using WebID-RSA
func Authenticate(req *http.Request) (string, error) {
	if len(req.Header.Get("Authorization")) == 0 {
		return "", nil
	}

	authH, err := ParseRSAAuthorizationHeader(req.Header.Get("Authorization"))
	if err != nil {
		return "", err
	}

	if len(authH.Source) == 0 || authH.Source != req.Host {
		return "", errors.New("Bad source URI for auth token: " + authH.Source + " -- possible MITM attack!")
	}

	claim := sha1.Sum([]byte(authH.Source + authH.Username + authH.Nonce))
	signature, err := base64.StdEncoding.DecodeString(authH.Signature)
	if err != nil {
		return "", errors.New(err.Error() + " in " + authH.Signature)
	}

	if len(authH.Username) == 0 || len(claim) == 0 || len(signature) == 0 {
		return "", errors.New("No WebID and/or claim found in the Authorization header.\n" + req.Header.Get("Authorization"))
	}

	// check that username has an HTTP scheme
	if !strings.HasPrefix(authH.Username, "http") {
		return "", errors.New("Username is not a valid HTTP URI: " + authH.Username)
	}

	// Decrypt and validate nonce from secure token
	err = ValidateToken(authH)
	if err != nil {
		return "", err
	}

	g := rdf.NewGraph(authH.Username)
	err = g.LoadURI(authH.Username)
	if err != nil {
		return "", err
	}

	for _, keyT := range g.All(rdf.NewResource(authH.Username), ns.cert.Get("key"), nil) {
		for range g.All(keyT.Object, ns.rdf.Get("type"), ns.cert.Get("RSAPublicKey")) {
			for _, pubN := range g.All(keyT.Object, ns.cert.Get("modulus"), nil) {
				keyN := unquote(pubN.Object.RawValue())
				pubE := g.One(keyT.Object, ns.cert.Get("exponent"), nil)
				if pubE == nil {
					return "", errors.New("No exponent found")
				}
				keyE := unquote(pubE.Object.RawValue())
				parser, err := ParseRSAPublicKeyNE("RSAPublicKey", keyN, keyE)
				if err == nil {
					err = parser.Verify(claim[:], signature)
					if err == nil {
						return authH.Username, nil
					}
				}
			}
		}
	}

	return "", err
}

func getOrigin(req *http.Request) string {
	scheme := "http"
	if req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https" {
		scheme += "s"
	}
	reqHost := req.Host
	if len(req.Header.Get("X-Forward-Host")) > 0 {
		reqHost = req.Header.Get("X-Forward-Host")
	}
	host, port, err := net.SplitHostPort(reqHost)
	if err != nil {
		host = reqHost
	}
	if len(host) == 0 {
		host = "localhost"
	}
	if len(port) > 0 {
		port = ":" + port
	}
	if (scheme == "https" && port == ":443") || (scheme == "http" && port == ":80") {
		port = ""
	}
	return scheme + "://" + host + port
}

func NewToken(req *http.Request) *Token {
	token := &Token{}
	token.Source = req.Host
	d := time.Duration(TokenDuration) * DurationScale
	token.Valid = time.Now().Add(d).UnixNano()
	token.Nonce = NewRandomID()
	return token
}

func ValidateToken(auth *RSAAuthorization) error {
	token := tokens[auth.Nonce]
	if token == nil {
		return errors.New("Could not find a token that matches " + auth.Nonce)
	}
	if time.Now().Local().UnixNano() > token.Valid {
		return errors.New("Token expired for " + auth.Username)
	}
	return nil
}

func saveToken(token *Token) {
	tokens[token.Nonce] = token
}

func getToken(id string) *Token {
	return tokens[id]
}