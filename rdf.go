package webidrsa

import (
	"strings"

	rdf "github.com/deiu/rdf2go"
)

var (
	ns = struct {
		rdf, cert, foaf NS
	}{
		rdf:  NewNS("http://www.w3.org/1999/02/22-rdf-syntax-ns#"),
		cert: NewNS("http://www.w3.org/ns/auth/cert#"),
		foaf: NewNS("http://xmlns.com/foaf/0.1/"),
	}
)

// NS is a generic namespace type
type NS string

// NewNS is used to set a new namespace
func NewNS(base string) (ns NS) {
	return NS(base)
}

// Get is used to return the prefix for a namespace
func (ns NS) Get(name string) (term rdf.Term) {
	return rdf.NewResource(string(ns) + name)
}

func brack(s string) string {
	if len(s) > 0 && s[0] == '<' {
		return s
	}
	if len(s) > 0 && s[len(s)-1] == '>' {
		return s
	}
	return "<" + s + ">"
}

func debrack(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] != '<' {
		return s
	}
	if s[len(s)-1] != '>' {
		return s
	}
	return s[1 : len(s)-1]
}

func defrag(s string) string {
	lst := strings.Split(s, "#")
	if len(lst) != 2 {
		return s
	}
	return lst[0]
}

func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] != '"' {
		return s
	}
	if s[len(s)-1] != '"' {
		return s
	}
	return s[1 : len(s)-1]
}
