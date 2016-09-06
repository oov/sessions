package cookie

import (
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/oov/sessions"
)

// Config is the set of session cookie properties.
type Config struct {
	// cookie domain/path scope (leave zeroed for requested resource scope)
	Domain string
	Path   string
	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'.
	// MaxAge>0 means Max-Age attribute present and given in seconds.
	MaxAge int
	// browser should prohibit non-HTTP (i.e. javascript) cookie access
	HTTPOnly bool
	// cookie may only be transferred over HTTPS
	Secure bool
}

type (
	// ReadFunc is callback function that read cookie data.
	// If not found, you must return http.ErrNoCookie.
	ReadFunc func(c []interface{}, name string) (string, error)
	// WriteFunc is callback function that write cookie data.
	WriteFunc func(c []interface{}, name, value string, cfg *Config) error
)

// Store stores Sessions in secure cookies (i.e. client-side)
type Store struct {
	// encodes and decodes signed and optionally encrypted cookie values
	Codecs []securecookie.Codec
	// configures session cookie properties of new Sessions
	Config *Config

	read  ReadFunc
	write WriteFunc
}

// NewStore returns a new Store which signs and optionally encrypts
// session cookies.
func NewStore(read ReadFunc, write WriteFunc, keyPairs ...[]byte) *Store {
	return &Store{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Config: &Config{
			Path:     "/",
			MaxAge:   3600 * 24 * 7, // 1 week
			HTTPOnly: true,
		},
		read:  read,
		write: write,
	}
}

func (s *Store) Context(c ...interface{}) sessions.Store {
	return &context{
		Store:   s,
		Context: c,
	}
}

type context struct {
	Store   *Store
	Context []interface{}
}

// New returns a new Session with the requested name and the store's config
// value.
func (c *context) New(name string) *sessions.Session {
	return &sessions.Session{
		Name:   name,
		Values: map[string]interface{}{},
		Store:  c,
	}
}

// Get returns the named Session from the Request. Returns an error if the
// session cookie cannot be found, the cookie verification fails, or an error
// occurs decoding the cookie value.
func (c *context) Get(name string) (*sessions.Session, error) {
	cookie, err := c.Store.read(c.Context, name)
	if err != nil {
		return nil, err
	}
	session := c.New(name)
	err = securecookie.DecodeMulti(name, cookie, &session.Values, c.Store.Codecs...)
	return session, err
}

// GetOrNew returns a Session with the requested name and the store's config
// value. If cookie can be found from the context, returns it.
func (c *context) GetOrNew(name string) (*sessions.Session, error) {
	sess, err := c.Get(name)
	if err == http.ErrNoCookie {
		return c.New(name), nil
	}
	return sess, err
}

// Save adds or updates the Session on the response via a signed and optionally
// encrypted session cookie. Session Values are encoded into the cookie value
// and the session Config sets cookie properties.
func (c *context) Save(session *sessions.Session) error {
	cookieValue, err := securecookie.EncodeMulti(session.Name, &session.Values, c.Store.Codecs...)
	if err != nil {
		return err
	}
	c.Store.write(c.Context, session.Name, cookieValue, c.Store.Config)
	return nil
}

// Destroy deletes the Session with the given name by issuing an expired
// session cookie with the same name.
func (c *context) Destroy(name string) error {
	c.Store.write(c.Context, name, "", &Config{
		MaxAge:   -1,
		Path:     c.Store.Config.Path,
		Domain:   c.Store.Config.Domain,
		HTTPOnly: c.Store.Config.HTTPOnly,
		Secure:   c.Store.Config.Secure,
	})
	return nil
}
