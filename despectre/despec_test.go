package despectre

import (
	"bytes"
	"crypto/sha1"
	"testing"
)

func TestNew(t *testing.T) {
	c, err := New(pagesize * 12)
	if err != nil {
		t.Errorf("New: %s", err)
	}
	defer c.Free()
	td := []byte("Very Secret Data you have there!")
	c.Store(td)
	_ = c.With(func(d [KeySize]byte) error {
		if bytes.Equal(c.protectedSecret[:], td) {
			t.Error("Wrong access")
		}
		if !bytes.Equal(d[:], td) {
			t.Error("Wrong secret")
		}
		return nil
	})
	_ = c.With(func(d [KeySize]byte) error {
		if bytes.Equal(c.protectedSecret[:], td) {
			t.Error("Wrong access")
		}
		if !bytes.Equal(d[:], td) {
			t.Error("Wrong secret")
		}
		return nil
	})
	h1 := sha1.Sum(c.protectedSecret[:])
	if err := c.Update(); err != nil {
		t.Errorf("Update failed: %s", err)
	}
	h2 := sha1.Sum(c.protectedSecret[:])
	if h1 == h2 {
		t.Error("Update failed")
	}
	_ = c.With(func(d [KeySize]byte) error {
		if bytes.Equal(c.protectedSecret[:], td) {
			t.Error("Wrong access after update")
		}
		if !bytes.Equal(d[:], td) {
			t.Error("Wrong secret after update")
		}
		return nil
	})
}
