package sessions

// Store is the interface for creating, reading, updating and destroying
// named Sessions.
type Store interface {
	New(name string) *Session
	Get(name string) (*Session, error)
	Save(session *Session) error
	Destroy(name string) error
}

// Session represents session.
type Session struct {
	Name   string
	Values map[string]interface{}
	Store  Store
}

// Save calls s.Store.Save.
func (s *Session) Save() error {
	return s.Store.Save(s)
}

// Destroy calls s.Store.Destroy.
func (s *Session) Destroy() error {
	return s.Store.Destroy(s.Name)
}
