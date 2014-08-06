package phpass

// Config represents the configuration options that PHPass takes
// Note that these are, essentially, ignored right now.
type Config struct {
	Count     int
	Portable  bool
	Algorithm string
	Itoa      string
}

// NewConfig returnes a new defaulted config struct for use with New()
func NewConfig() *Config {
	return &Config{
		Count:     8,
		Portable:  true,
		Algorithm: "bcrypt",
		Itoa:      "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	}
}
