package phpass

import (
	"bytes"
	"crypto/md5"
	"testing"
)

func TestEncode(t *testing.T) {
	var h = New(nil)
	if v := h.encode([]byte("foobar"), 6); string(v) != "axqPW3aQ" {
		t.Errorf("expected 'axqPW3aQ', got %q", string(v))
	}

	var m = md5.New()
	m.Write([]byte("blah"))
	if v := h.encode(m.Sum(nil), 16); string(v) != `jt/o0gOJJK6YIgCwJKV6N1` {
		t.Errorf("expected 'jt/o0gOJJK6YIgCwJKV6N1', got %q", string(v))
	}
}

func TestSalt(t *testing.T) {
	var h = New(nil)
	s1 := h.salt()
	s2 := h.salt()
	if 0 == bytes.Compare(s1, s2) {
		t.Errorf("expected different salts, got %q both times", string(s1))
	}
}

func TestCrypt(t *testing.T) {
	var h = New(nil)
	v, e := h.crypt([]byte("QqWwEeRrTtYy"), []byte(`$P$BU7c29K11fx.vbNBsqafkEDO8GC/280`))
	if e != nil {
		t.Errorf("Expected no error, got %s", e.Error())
	}
	if !bytes.Equal([]byte(`$P$BU7c29K11fx.vbNBsqafkEDO8GC/280`), v) {
		t.Errorf("Expected returned hash to match, got %s", v)
	}

	v, e = h.crypt([]byte("QqWwEeRrTtYy"), []byte(`$H$BU7c29K11fx.vbNBsqafkEDO8GC/280`))
	if e != nil {
		t.Errorf("Expected no error, got %s", e.Error())
	}
	if !bytes.Equal([]byte(`$H$BU7c29K11fx.vbNBsqafkEDO8GC/280`), v) {
		t.Errorf("Expected returned hash to match, got %s", v)
	}

	v, e = h.crypt([]byte("QqWwEeRrTtYy"), []byte(`$P$zU7c29K11fx.vbNBsqafkEDO8GC/280`))
	if e != errBadCount {
		t.Errorf("Expected errBadCount, got %#v", e)
	}
	if !bytes.Equal([]byte(`*0`), v) {
		t.Errorf("Expected *0, got %s", v)
	}

	v, e = h.crypt([]byte("QqWwEeRrTtYy"), []byte(`$Z$BU7c29K11fx.vbNBsqafkEDO8GC/280`))
	if e != errBadID {
		t.Errorf("Expected errBadID, got %#v", e)
	}
	if !bytes.Equal([]byte(`*0`), v) {
		t.Errorf("Expected *0, got %s", v)
	}

	v, e = h.crypt([]byte("QqWwEeRrTtYy"), []byte(`*0$BU7c29K11fx.vbNBsqafkEDO8GC/280`))
	if e != errBadID {
		t.Errorf("Expected no errBadId, got %#v", e)
	}
	if !bytes.Equal([]byte(`*1`), v) {
		t.Errorf("Expected *1, got %s", v)
	}
}

func TestCheck(t *testing.T) {
	var h = New(nil)
	if v := h.Check([]byte("QqWwEeRrTtYy"), []byte(`$P$BU7c29K11fx.vbNBsqafkEDO8GC/280`)); !v {
		t.Errorf("Expected true, got false")
	}
	if v := h.Check([]byte("qqWwEeRrTtYy"), []byte(`$P$BU7c29K11fx.vbNBsqafkEDO8GC/280`)); v {
		t.Errorf("Expected false, got true")
	}
}

func TestHash(t *testing.T) {
	var h = New(nil)
	hashedPW, err := h.Hash([]byte("345jkhrlfkwhpf98q3u4pljhqenwlfkjashd"))
	if err != nil {
		t.Errorf("Expected no error, got %s", err.Error())
	}
	if !h.Check([]byte("345jkhrlfkwhpf98q3u4pljhqenwlfkjashd"), hashedPW) {
		t.Errorf("Expected Check to return true for valid password and generated hash")
	}
	if h.Check([]byte("345jkhrlfkw_____________qenwlfkjashd"), hashedPW) {
		t.Errorf("Expected Check to return false for invalid password and generated hash")
	}
}
