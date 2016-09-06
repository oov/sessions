package echo

import (
	"net/http"
	"time"

	"github.com/labstack/echo"
	"github.com/oov/sessions/cookie"
)

func NewStore(keyPairs ...[]byte) *cookie.Store {
	return cookie.NewStore(read, write, keyPairs...)
}

func getContext(c []interface{}) echo.Context {
	if len(c) == 1 {
		if ctx, ok := c[0].(echo.Context); ok {
			return ctx
		}
	}
	panic("session/cookie/echo: You have passed wrong context to github.com/oov/sessions/cookie.Store.Context.")
}

func read(c []interface{}, name string) (string, error) {
	cookie, err := getContext(c).Cookie(name)
	if err != nil {
		if err == echo.ErrCookieNotFound {
			return "", http.ErrNoCookie
		}
		return "", err
	}
	return cookie.Value(), nil
}

func write(c []interface{}, name, value string, cfg *cookie.Config) error {
	cookie := &echo.Cookie{}
	cookie.SetName(name)
	cookie.SetValue(value)
	cookie.SetDomain(cfg.Domain)
	cookie.SetPath(cfg.Path)
	cookie.SetHTTPOnly(cfg.HTTPOnly)
	cookie.SetSecure(cfg.Secure)
	if expires, present := cookieExpires(cfg.MaxAge); present {
		cookie.SetExpires(expires)
	}
	getContext(c).SetCookie(cookie)
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
