# webid-rsa
[![](https://img.shields.io/badge/project-Solid-7C4DFF.svg?style=flat-square)](https://github.com/solid/solid)
[![Build Status](https://travis-ci.org/deiu/webid-rsa.svg?branch=master)](https://travis-ci.org/deiu/webid-rsa)
[![Coverage Status](https://coveralls.io/repos/github/deiu/webid-rsa/badge.svg?branch=master)](https://coveralls.io/github/deiu/webid-rsa?branch=master)


WebID-RSA authentication library in Go

# Install
```
go get -u github.com/deiu/webid-rsa
```

# Example

```golang
package main

import (
	"net/http"
	"github.com/deiu/webid-rsa"
)

func main() {
	handler := http.NewServeMux()

	handler.Handle("/admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		user := ""
		authz := req.Header.Get("Authorization")
		if len(authz) > 0 {
			user, _ = webidrsa.Authenticate(req)
		}
		if len(user) == 0 {
			authn := webidrsa.NewAuthenticateHeader(req)
			w.Header().Set("WWW-Authenticate", authn)
			w.WriteHeader(401)
			return
		}

		w.Write([]byte(user))
		w.WriteHeader(200)
		return
	}))

	http.ListenAndServe(":8888", handler)
}
```

# Protocol details

WebID-RSA is somewhat similar to [WebID-TLS](https://www.w3.org/2005/Incubator/webid/spec/tls/), in that a public RSA key is published in the WebID profile, and the user will sign a token with the corresponding private key that matches the public key in the profile.

The client receives a secure token from the server, which it signs and then sends back to the server. The implementation of WebID-RSA is similar to [Digest
access authentication](https://tools.ietf.org/html/rfc2617) in HTTP, in that it
reuses similar headers.

Here is a step by step example that covers the authentication handshake.

First, a client attempts to access a protected resource at
`https://example.org/data/`.

REQUEST:

```
GET /data/ HTTP/1.1
Host: example.org
```

RESPONSE:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: WebID-RSA source="example.org", nonce="somethingSecure"
```

Next, the client sets the username value to the user's WebID and signs the
`SHA1` hash of the concatenated value of **source + username + nonce** before
resending the request. The signature must use the `PKCS1v15` standard and it
must be `base64` encoded.

It is important that clients return the proper source value they received from
the server, in order to avoid man-in-the-middle attacks on non-HTTPS connections. Also note that the server must send it's own URI (**source**) together with the token, otherwise a [MitM](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) can forward the claim to the client; the server will also expect that clients return the same server URI.

REQUEST:

```
GET /data/ HTTP/1.1
Host: example.org
Authorization: WebID-RSA source="example.org",
                         username="https://alice.example.org/card#me",
                         nonce="somethingSecure",
                         sig="base64(sig(SHA1(SourceUsernameNonce)))"
```

RESPONSE:

```
HTTP/1.1 200 OK
```
