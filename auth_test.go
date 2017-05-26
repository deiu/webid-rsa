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
	handler.Handle("/mod", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
	return handler
}

func TestAuthenticate(t *testing.T) {
	user1 := testMockServer.URL + "/mod#me"

	req, err := http.NewRequest("GET", testMockServer.URL, nil)
	assert.NoError(t, err)

	// generate token
	token := NewToken(req)
	saveToken(token)
	// Load private key
	signer, err := ParseRSAPrivatePEMKey(privKey)
	assert.NoError(t, err)

	claim := sha1.Sum([]byte(token.Source + user1 + token.Nonce))
	signed, err := signer.Sign(claim[:])
	assert.NoError(t, err)
	b64Sig := base64.StdEncoding.EncodeToString(signed)
	assert.NotEmpty(t, b64Sig)

	authHeader := `WebID-RSA source="` + token.Source + `", username="` + user1 + `", nonce="` + token.Nonce + `", sig="` + b64Sig + `"`

	req, err = http.NewRequest("GET", testMockServer.URL+"/mod", nil)
	assert.NoError(t, err)
	req.Header.Add("Authorization", authHeader)
	res, err := testClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "text/turtle", res.Header.Get("Content-Type"))

	authUser, err := Authenticate(req)
	assert.NoError(t, err)
	assert.Equal(t, user1, authUser)
}

func TestParseRSAAuthorizationHeader(t *testing.T) {
	_, err := ParseRSAAuthorizationHeader("")
	assert.Error(t, err)

	h := "WebID-Other source=\"http://server.org/\""
	_, err = ParseRSAAuthorizationHeader(h)
	assert.Error(t, err)

	h = "WebID-RSA source=\"http://server.org/\", username=\"http://example.org/\", nonce=\"string1\", sig=\"string2\""
	p, err := ParseRSAAuthorizationHeader(h)
	assert.NoError(t, err)
	assert.Equal(t, "http://server.org/", p.Source)
	assert.Equal(t, "http://example.org/", p.Username)
	assert.Equal(t, "string1", p.Nonce)
	assert.Equal(t, "string2", p.Signature)

	h = "WebID-RSA source=\"http://server.org/\", \nusername=\"http://example.org/\", \nnonce=\"string1\",\n sig=\"string2\""
	p, err = ParseRSAAuthorizationHeader(h)
	assert.NoError(t, err)
	assert.Equal(t, "http://server.org/", p.Source)
	assert.Equal(t, "http://example.org/", p.Username)
	assert.Equal(t, "string1", p.Nonce)
	assert.Equal(t, "string2", p.Signature)
}

func TestParseRSAAuthenticateHeader(t *testing.T) {
	_, err := ParseRSAAuthenticateHeader("")
	assert.Error(t, err)

	h := `WebID-Other source="http://server.org/"`
	_, err = ParseRSAAuthenticateHeader(h)
	assert.Error(t, err)

	h = `WebID-RSA source="http://server.org/", nonce="string1"`
	p, err := ParseRSAAuthenticateHeader(h)
	assert.NoError(t, err)
	assert.Equal(t, "string1", p.Nonce)
	assert.Equal(t, "http://server.org/", p.Source)

}

func TestAuthToken(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	assert.NoError(t, err)
	token := NewToken(req)
	assert.Equal(t, req.Host, token.Source)
	assert.Equal(t, randLength, len(token.Nonce))
	saveToken(token)
	assert.NotNil(t, getToken(token.Nonce))

	h := "WebID-RSA source=\"" + token.Source + "\", username=\"http://example.org/\", nonce=\"" + token.Nonce + "\", sig=\"string2\""
	auth, err := ParseRSAAuthorizationHeader(h)
	assert.NoError(t, err)
	err = ValidateToken(auth)
	assert.NoError(t, err)

	err = ValidateToken(&RSAAuthorization{})
	assert.Error(t, err)

	DurationScale = time.Microsecond
	token = NewToken(req)
	saveToken(token)
	h = "WebID-RSA source=\"" + token.Source + "\", username=\"http://example.org/\", nonce=\"" + token.Nonce + "\", sig=\"string2\""
	time.Sleep(time.Millisecond * 1)
	auth, err = ParseRSAAuthorizationHeader(h)
	assert.NoError(t, err)
	err = ValidateToken(auth)
	assert.Error(t, err)
	DurationScale = time.Minute
}

func TestOrigin(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	assert.NoError(t, err)
	req.Header.Add("X-Forward-Host", "example.org")
	assert.Equal(t, "http://example.org", getOrigin(req))

	req, err = http.NewRequest("GET", "/foo", nil)
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost", getOrigin(req))

	req, err = http.NewRequest("GET", "http://localhost:80", nil)
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost", getOrigin(req))

	req, err = http.NewRequest("GET", "http://example.com", nil)
	assert.NoError(t, err)
	req.Header.Set("X-Forwarded-Proto", "https")
	assert.Equal(t, "https://example.com", getOrigin(req))
}
