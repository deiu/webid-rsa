package webidrsa

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
