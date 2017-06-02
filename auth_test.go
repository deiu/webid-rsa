package webidrsa

import (
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	testMockServer *httptest.Server
	testClient     = &http.Client{}
)

func init() {
	handler := MockServer()
	testMockServer = httptest.NewUnstartedServer(handler)
	testMockServer.Start()
	testMockServer.URL = strings.Replace(testMockServer.URL, "127.0.0.1", "localhost", 1)
}

func MockServer() http.Handler {
	handler := http.NewServeMux()
	handler.Handle("/real", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		user := ""
		authz := req.Header.Get("Authorization")
		if len(authz) > 0 {
			user, _ = Authenticate(req)
		}
		if len(user) == 0 {
			authH := NewAuthenticateHeader(req)
			w.Header().Set("WWW-Authenticate", authH)
			w.WriteHeader(401)
			return
		}

		w.Header().Set("User", user)
		w.WriteHeader(200)
		return
	}))
	handler.Handle("/ok", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		webidProfile := `@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
<#me> a <http://xmlns.com/foaf/0.1/Person> ;
	<http://www.w3.org/ns/auth/cert#key> <#one> .

<#one>
    a <http://www.w3.org/ns/auth/cert#RSAPublicKey> ;
    <http://www.w3.org/ns/auth/cert#exponent> "65537"^^<http://www.w3.org/2001/XMLSchema#int> ;
    <http://www.w3.org/ns/auth/cert#modulus> "c2144346c37df21a2872f76a438d94219740b7eab3c98fe0af7d20bcfaadbc871035eb5405354775df0b824d472ad10776aac05eff6845c9cd83089260d21d4befcfba67850c47b10e7297dd504f477f79bf86cf85511e39b8125e0cad474851c3f1b1ca0fa92ff053c67c94e8b5cfb6c63270a188bed61aa9d5f21e91ac6cc9"^^<http://www.w3.org/2001/XMLSchema#hexBinary> .
`
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(200)
		w.Write([]byte(webidProfile))
		return
	}))
	handler.Handle("/bad", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		webidProfile := `@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
<#me> a <http://xmlns.com/foaf/0.1/Person> ;
	<http://www.w3.org/ns/auth/cert#key> <#one> .

<#one>
    a <http://www.w3.org/ns/auth/cert#RSAPublicKey> ;
    <http://www.w3.org/ns/auth/cert#modulus> "c2144346c37df21a2872f76a438d94219740b7eab3c98fe0af7d20bcfaadbc871035eb5405354775df0b824d472ad10776aac05eff6845c9cd83089260d21d4befcfba67850c47b10e7297dd504f477f79bf86cf85511e39b8125e0cad474851c3f1b1ca0fa92ff053c67c94e8b5cfb6c63270a188bed61aa9d5f21e91ac6cc9"^^<http://www.w3.org/2001/XMLSchema#hexBinary> .
`
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(200)
		w.Write([]byte(webidProfile))
		return
	}))

	handler.Handle("/exp", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		webidProfile := `@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
<#me> a <http://xmlns.com/foaf/0.1/Person> ;
	<http://www.w3.org/ns/auth/cert#key> <#one> .

<#one>
    a <http://www.w3.org/ns/auth/cert#RSAPublicKey> ;
    <http://www.w3.org/ns/auth/cert#exponent> "1"^^<http://www.w3.org/2001/XMLSchema#int> ;
    <http://www.w3.org/ns/auth/cert#modulus> "c2144346c37df21a2872f76a438d94219740b7eab3c98fe0af7d20bcfaadbc871035eb5405354775df0b824d472ad10776aac05eff6845c9cd83089260d21d4befcfba67850c47b10e7297dd504f477f79bf86cf85511e39b8125e0cad474851c3f1b1ca0fa92ff053c67c94e8b5cfb6c63270a188bed61aa9d5f21e91ac6cc9"^^<http://www.w3.org/2001/XMLSchema#hexBinary> .
`
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(200)
		w.Write([]byte(webidProfile))
		return
	}))
	return handler
}

func TestAuthenticateOK(t *testing.T) {
	user := testMockServer.URL + "/ok#me"

	req, err := http.NewRequest("GET", testMockServer.URL, nil)
	assert.NoError(t, err)

	// generate token
	token := NewToken(req)
	saveToken(token)
	// Load private key
	signer, err := ParsePrivatePEMKey(privKey)
	assert.NoError(t, err)

	claim := sha1.Sum([]byte(token.Source + user + token.Nonce))
	signed, err := signer.Sign(claim[:])
	assert.NoError(t, err)
	b64Sig := base64.StdEncoding.EncodeToString(signed)
	assert.NotEmpty(t, b64Sig)

	authHeader := `WebID-RSA source="` + token.Source + `", username="` + user + `", nonce="` + token.Nonce + `", sig="` + b64Sig + `"`

	req, err = http.NewRequest("GET", testMockServer.URL+"/ok", nil)
	assert.NoError(t, err)
	req.Header.Add("Authorization", authHeader)
	res, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "text/turtle", res.Header.Get("Content-Type"))

	authUser, err := Authenticate(req)
	assert.NoError(t, err)
	assert.Equal(t, user, authUser)
	assert.Nil(t, getToken(token.Nonce))

	req, err = http.NewRequest("GET", testMockServer.URL+"/real", nil)
	assert.NoError(t, err)
	res, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, res.StatusCode)
	assert.Empty(t, res.Header.Get("User"))

	authz, err := ParseAuthenticateHeader(res.Header.Get("WWW-Authenticate"))
	assert.NoError(t, err)

	claim = sha1.Sum([]byte(authz.Source + user + authz.Nonce))
	signed, err = signer.Sign(claim[:])
	assert.NoError(t, err)
	b64Sig = base64.StdEncoding.EncodeToString(signed)
	assert.NotEmpty(t, b64Sig)

	authHeader = `WebID-RSA source="` + authz.Source + `", username="` + user + `", nonce="` + authz.Nonce + `", sig="` + b64Sig + `"`
	req, err = http.NewRequest("GET", testMockServer.URL+"/real", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", authHeader)
	res, err = testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, user, res.Header.Get("User"))
}

func TestAuthenticateBad(t *testing.T) {
	user := testMockServer.URL + "/bad#me"

	req, err := http.NewRequest("GET", testMockServer.URL, nil)
	assert.NoError(t, err)

	// Load private key
	signer, err := ParsePrivatePEMKey(privKey)
	assert.NoError(t, err)

	// bad token
	DurationScale = time.Microsecond
	token := NewToken(req)
	saveToken(token)

	claim := sha1.Sum([]byte(token.Source + user + token.Nonce))
	signed, err := signer.Sign(claim[:])
	assert.NoError(t, err)
	b64Sig := base64.StdEncoding.EncodeToString(signed)
	assert.NotEmpty(t, b64Sig)

	authHeader := `WebID-RSA source="` + token.Source + `", username="` + user + `", nonce="` + token.Nonce + `", sig="` + b64Sig + `"`
	time.Sleep(time.Millisecond * 1)
	req.Header.Add("Authorization", authHeader)
	authUser, err := Authenticate(req)
	assert.Error(t, err)
	assert.Empty(t, authUser)
	assert.Nil(t, getToken(token.Nonce))
	DurationScale = time.Minute

	// generate token
	token = NewToken(req)
	saveToken(token)

	claim = sha1.Sum([]byte(token.Source + user + token.Nonce))
	signed, err = signer.Sign(claim[:])
	assert.NoError(t, err)
	b64Sig = base64.StdEncoding.EncodeToString(signed)
	assert.NotEmpty(t, b64Sig)

	authHeader = `WebID-RSA source="` + token.Source + `", username="` + user + `", nonce="` + token.Nonce + `", sig="` + b64Sig + `"`

	req, err = http.NewRequest("GET", testMockServer.URL+"/bad", nil)
	assert.NoError(t, err)
	req.Header.Add("Authorization", authHeader)
	res, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "text/turtle", res.Header.Get("Content-Type"))

	authUser, err = Authenticate(req)
	assert.Error(t, err)
	assert.Empty(t, authUser)

	authHeader = `WebID-DSA source="` + token.Source + `", username="` + user + `", nonce="` + token.Nonce + `", sig="` + b64Sig + `"`
	req, err = http.NewRequest("GET", testMockServer.URL+"/bad", nil)
	assert.NoError(t, err)
	authUser, err = Authenticate(req)
	assert.NoError(t, err)
	assert.Empty(t, authUser)

	authHeader = `WebID-RSA source="badsource", username="` + user + `", nonce="` + token.Nonce + `", sig="` + b64Sig + `"`
	req.Header.Set("Authorization", authHeader)
	authUser, err = Authenticate(req)
	assert.Error(t, err)
	assert.Empty(t, authUser)

	authHeader = `WebID-RSA source="` + token.Source + `", username="` + user + `", nonce="` + token.Nonce + `", sig="f00"`
	req.Header.Set("Authorization", authHeader)
	authUser, err = Authenticate(req)
	assert.Error(t, err)
	assert.Empty(t, authUser)

	authHeader = `WebID-RSA source="` + token.Source + `", username="", nonce="` + token.Nonce + `", sig="` + b64Sig + `"`
	req.Header.Set("Authorization", authHeader)
	authUser, err = Authenticate(req)
	assert.Error(t, err)
	assert.Empty(t, authUser)

	authHeader = `WebID-RSA source="` + token.Source + `", username="f00", nonce="` + token.Nonce + `", sig="` + b64Sig + `"`
	req.Header.Set("Authorization", authHeader)
	authUser, err = Authenticate(req)
	assert.Error(t, err)
	assert.Empty(t, authUser)

	authHeader = `WebID-RSA source="` + token.Source + `", username="https://example", nonce="` + token.Nonce + `", sig="` + b64Sig + `"`
	req.Header.Set("Authorization", authHeader)
	authUser, err = Authenticate(req)
	assert.Error(t, err)
	assert.Empty(t, authUser)

	authHeader = `WebID-DSA source="` + token.Source + `", username="` + user + `", nonce="` + token.Nonce + `", sig="` + b64Sig + `"`
	req.Header.Set("Authorization", authHeader)
	authUser, err = Authenticate(req)
	assert.Error(t, err)
	assert.Empty(t, authUser)

	user = testMockServer.URL + "/exp#me"
	token = NewToken(req)
	saveToken(token)

	claim = sha1.Sum([]byte(token.Source + user + token.Nonce))
	signed, err = signer.Sign(claim[:])
	assert.NoError(t, err)
	b64Sig = base64.StdEncoding.EncodeToString(signed)
	assert.NotEmpty(t, b64Sig)

	authHeader = `WebID-RSA source="` + token.Source + `", username="` + user + `", nonce="` + token.Nonce + `", sig="` + b64Sig + `"`
	req.Header.Set("Authorization", authHeader)
	authUser, err = Authenticate(req)
	assert.NoError(t, err)
	assert.Empty(t, authUser)
}

func TestParseAuthorizationHeader(t *testing.T) {
	_, err := ParseAuthorizationHeader("")
	assert.Error(t, err)

	h := "WebID-RSA"
	_, err = ParseAuthorizationHeader(h)
	assert.Error(t, err)

	h = "WebID-RSA foo"
	_, err = ParseAuthorizationHeader(h)
	assert.NoError(t, err)

	h = "WebID-RSA source=foo"
	_, err = ParseAuthorizationHeader(h)
	assert.NoError(t, err)

	h = "WebID-RSA source=\"http://server.org/\", username=\"http://example.org/\", nonce=\"string1\", sig=\"string2\""
	p, err := ParseAuthorizationHeader(h)
	assert.NoError(t, err)
	assert.Equal(t, "WebID-RSA", p.Type)
	assert.Equal(t, "http://server.org/", p.Source)
	assert.Equal(t, "http://example.org/", p.Username)
	assert.Equal(t, "string1", p.Nonce)
	assert.Equal(t, "string2", p.Signature)

	h = "WebID-RSA source=\"http://server.org/\", \nusername=\"http://example.org/\", \nnonce=\"string1\",\n sig=\"string2\""
	p, err = ParseAuthorizationHeader(h)
	assert.NoError(t, err)
	assert.Equal(t, "WebID-RSA", p.Type)
	assert.Equal(t, "http://server.org/", p.Source)
	assert.Equal(t, "http://example.org/", p.Username)
	assert.Equal(t, "string1", p.Nonce)
	assert.Equal(t, "string2", p.Signature)
}

func TestNewAuthenticateHeader(t *testing.T) {
	req, err := http.NewRequest("GET", testMockServer.URL, nil)
	assert.NoError(t, err)
	authH := NewAuthenticateHeader(req)

	parsed, err := ParseAuthenticateHeader(authH)
	assert.NoError(t, err)
	assert.Equal(t, randLength, len(parsed.Nonce))
	assert.Equal(t, req.Host, parsed.Source)
}

func TestParseAuthenticateHeader(t *testing.T) {
	_, err := ParseAuthenticateHeader("")
	assert.Error(t, err)

	h := `WebID-Other source="http://server.org/"`
	_, err = ParseAuthenticateHeader(h)
	assert.Error(t, err)

	h = `WebID-RSA`
	_, err = ParseAuthenticateHeader(h)
	assert.Error(t, err)

	h = `WebID-RSA foo`
	_, err = ParseAuthenticateHeader(h)
	assert.NoError(t, err)

	h = `WebID-RSA source="http://server.org/", nonce="string1"`
	p, err := ParseAuthenticateHeader(h)
	assert.NoError(t, err)
	assert.Equal(t, "string1", p.Nonce)
	assert.Equal(t, "http://server.org/", p.Source)
}

func TestAuthToken(t *testing.T) {
	req, err := http.NewRequest("GET", testMockServer.URL, nil)
	assert.NoError(t, err)
	token := NewToken(req)
	assert.Equal(t, req.Host, token.Source)
	assert.Equal(t, randLength, len(token.Nonce))
	saveToken(token)
	assert.NotNil(t, getToken(token.Nonce))

	h := "WebID-RSA source=\"" + token.Source + "\", username=\"http://example.org/\", nonce=\"" + token.Nonce + "\", sig=\"string2\""
	auth, err := ParseAuthorizationHeader(h)
	assert.NoError(t, err)
	err = ValidateToken(auth)
	assert.NoError(t, err)

	err = ValidateToken(&Authorization{})
	assert.Error(t, err)

	DurationScale = time.Microsecond
	token = NewToken(req)
	saveToken(token)
	h = "WebID-RSA source=\"" + token.Source + "\", username=\"http://example.org/\", nonce=\"" + token.Nonce + "\", sig=\"string2\""
	time.Sleep(time.Millisecond * 1)
	auth, err = ParseAuthorizationHeader(h)
	assert.NoError(t, err)
	err = ValidateToken(auth)
	assert.Error(t, err)
	assert.Nil(t, getToken(token.Nonce))
	DurationScale = time.Minute
}

func TestOrigin(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	assert.NoError(t, err)
	req.Header.Add("X-Forward-Host", "example.org")
	assert.Equal(t, "http://example.org", GetOrigin(req))

	req, err = http.NewRequest("GET", "/foo", nil)
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost", GetOrigin(req))

	req, err = http.NewRequest("GET", "http://localhost:80", nil)
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost", GetOrigin(req))

	req, err = http.NewRequest("GET", "http://example.com", nil)
	assert.NoError(t, err)
	req.Header.Set("X-Forwarded-Proto", "https")
	assert.Equal(t, "https://example.com", GetOrigin(req))
}
