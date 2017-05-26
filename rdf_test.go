package webidrsa

import (
	"testing"

	// rdf "github.com/deiu/rdf2go"
	"github.com/stretchr/testify/assert"
)

func TestNewNS(t *testing.T) {
	key := brack("http://www.w3.org/ns/auth/cert#key")
	rtype := brack("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
	person := brack("http://xmlns.com/foaf/0.1/Person")

	assert.Equal(t, rtype, ns.rdf.Get("type").String())
	assert.Equal(t, key, ns.cert.Get("key").String())
	assert.Equal(t, person, ns.foaf.Get("Person").String())
}

func TestUnquote(t *testing.T) {
	s := `"`
	assert.Equal(t, s, unquote(s))

	s = `foo"`
	assert.Equal(t, s, unquote(s))

	s = `"foo`
	assert.Equal(t, s, unquote(s))

	s = `foo`
	assert.Equal(t, s, unquote(s))

	s = `"foo"`
	assert.Equal(t, "foo", unquote(s))

}

func TestRDFBrack(t *testing.T) {
	assert.Equal(t, "<test>", brack("test"))
	assert.Equal(t, "<test", brack("<test"))
	assert.Equal(t, "test>", brack("test>"))
}

func TestRDFDebrack(t *testing.T) {
	assert.Equal(t, "a", debrack("a"))
	assert.Equal(t, "test", debrack("<test>"))
	assert.Equal(t, "<test", debrack("<test"))
	assert.Equal(t, "test>", debrack("test>"))
}

func TestDefrag(t *testing.T) {
	assert.Equal(t, "test", defrag("test"))
	assert.Equal(t, "test", defrag("test#me"))
}
