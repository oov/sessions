package echo

import (
	"net/http"
	"time"

	"github.com/oov/sessions/cookie"
)

func NewStore(keyPairs ...[]byte) *cookie.Store {
	return cookie.NewStore(read, write, keyPairs...)
}

func getContext(c []interface{}) (http.ResponseWriter, *http.Request) {
	if len(c) == 2 {
		w, ok := c[0].(http.ResponseWriter)
		r, ok2 := c[1].(*http.Request)
		if ok && ok2 {
			return w, r
		}
	}
	panic("session/cookie/std: You have passed wrong context to github.com/oov/sessions/cookie.Store.Context.")
}

func read(c []interface{}, name string) (string, error) {
	_, r := getContext(c)
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func write(c []interface{}, name, value string, cfg *cookie.Config) error {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		MaxAge:   cfg.MaxAge,
		HttpOnly: cfg.HTTPOnly,
		Secure:   cfg.Secure,
	}
	if expires, present := cookieExpires(cfg.MaxAge); present {
		cookie.Expires = expires
	}
	w, _ := getContext(c)
	http.SetCookie(w, cookie)
	return nil
}

// cookieExpires takes the MaxAge number of seconds a Cookie should be valid
// and returns the Expires time.Time and whether the attribtue should be set.
// http://golang.org/src/net/http/cookie.go?s=618:801#L23
func cookieExpires(maxAge int) (time.Time, bool) {
	if maxAge > 0 {
		d := time.Duration(maxAge) * time.Second
		return time.Now().Add(d), true
	} else if maxAge < 0 {
		return time.Unix(1, 0), true // first second of the epoch
	}
	return time.Time{}, false
}
