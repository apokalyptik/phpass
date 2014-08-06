// Package phpass Provides the ability to create and validate PHPass hashed
// passwords.  See http://www.openwall.com/phpass/ for more details. The code
// here is more or less a direct port of the PHP implimentation found inside
// the official download. Or will be once it has been completed.
//
// The code as it stands is not 100% complete in that it does not work with
// all of the options that can/should be speficied. It does work with the
// default options, and is compatible with WordPress's use of PHPass for
// hasing passwords in the database
package phpass

// BUG(): Non-Default configurations are not supported at this time. Obviously
// they are planned, but have not been gotten around to yet.

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"hash"
	"strings"
)

var (
	errBadID    = errors.New("bad ID")
	errBadCount = errors.New("bad count")
)

// Hash allows you to hash, and validate PHPass hashed passwords. The Hash
// structure is not thread safe. If you plan to use a single hasher you'll want
// to synchronize with your own syc.Mutex
type Hash struct {
	Config *Config
	MD5er  hash.Hash
}

// Hash takes a returns a PHPass hash given the input password
func (h *Hash) Hash(pw []byte) ([]byte, error) {
	// $random = $this->get_random_bytes(6);
	// $this->crypt_private($password, $this->gensalt_private($random));
	return h.crypt(pw, h.salt())
}

// Check validates the given password against the given hash, returning true if
// they match, otherwise false
func (h *Hash) Check(pw, pwhash []byte) bool {
	generated, err := h.crypt(pw, pwhash)
	if err != nil {
		return false
	}
	//if generated[0] == 42 {
	//	generated = ?crypt?(password, hash)
	//}
	return bytes.Equal(generated, pwhash)
}

func (h *Hash) crypt(pw, pwhash []byte) ([]byte, error) {
	var rval []byte
	if bytes.Equal(pwhash[0:2], []byte("*0")) {
		rval = []byte("*1")
	} else {
		rval = []byte("*0")
	}

	var id = string(pwhash[0:3])
	if id != "$P$" && id != "$H$" {
		return rval, errBadID
	}

	var count = uint(strings.IndexByte(h.Config.Itoa, pwhash[3]))
	if count < 7 || count > 30 {
		return rval, errBadCount
	}
	count = 1 << count

	var salt = pwhash[4:12]
	h.MD5er.Reset()
	h.MD5er.Write(salt)
	h.MD5er.Write(pw)
	var checksum = h.MD5er.Sum(nil)
	for i := uint(0); i < count; i++ {
		h.MD5er.Reset()
		h.MD5er.Write(checksum)
		h.MD5er.Write(pw)
		checksum = h.MD5er.Sum(nil)
	}
	rval = []byte{}
	rval = append(rval, pwhash[:12]...)
	rval = append(rval, h.encode(checksum, 16)...)
	return rval, nil
}

func (h *Hash) encode(input []byte, count int) []byte {
	var rval = []byte{}
	var i = 0
	for {
		value := int(input[i])
		i++
		rval = append(rval, h.Config.Itoa[(value&0x3f)])

		if i < count {
			value = value | int(input[i])<<8
		}
		rval = append(rval, h.Config.Itoa[((value>>6)&0x3f)])

		if i >= count {
			break
		}
		i++

		if i < count {
			value = value | int(input[i])<<16
		}
		rval = append(rval, h.Config.Itoa[((value>>12)&0x3f)])

		if i >= count {
			break
		}
		i++

		rval = append(rval, h.Config.Itoa[((value>>18)&0x3f)])
		if i >= count {
			break
		}
	}
	return rval
}

func (h *Hash) salt() []byte {
	var input = make([]byte, 6)
	if _, err := rand.Read(input); err != nil {
		panic(err)
	}
	var i = h.Config.Count + 5
	if i > 30 {
		i = 30
	}
	return append([]byte("$P$"), append([]byte{h.Config.Itoa[i]}, h.encode(input, 6)...)...)
}

// New returns a new Hash structure against which you can make Hash() and
// Check() calls for creating and validating PHPass hashed passwords. If
// you pass nil as the config a default config will be provided for you.
func New(config *Config) *Hash {
	if config == nil {
		config = NewConfig()
	}
	if config.Count < 4 || config.Count > 31 {
		config.Count = 8
	}
	return &Hash{
		Config: config,
		MD5er:  md5.New(),
	}
}
