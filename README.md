# webid-rsa
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
			authH := webidrsa.NewRSAAuthenticateHeader(req)
			w.Header().Set("WWW-Authenticate", authH)
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