package despectre

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"github.com/cypherlock-pf/securemem/guardedmem"
	"io"
)

const (
	pagesize    = 4096
	alignBuf    = 64
	randKeySize = aes.BlockSize
	guardSize   = pagesize - alignBuf

	// KeySize is the exact size of a key to store in a cell.
	KeySize = sha512.Size256
)

// set all bytes in a byteslize to 0x00
func setZero(d []byte) {
	for i := 0; i < len(d); i++ {
		d[i] = 0x00
	}
}

// Cell protects a secret of the size KeySize.
type Cell struct {
	protectedSecret [KeySize]byte
	decryptedSecret [KeySize]byte

	guardKey [KeySize]byte
	rollKey  [KeySize]byte
	tmpkey   [randKeySize]byte
	guard    *guard
	size     int
}

// Free the memory allocated for the cell.
func (c *Cell) Free() {
	if c == nil {
		return
	}
	if c.guard != nil {
		c.guard.free()
	}
	setZero(c.protectedSecret[:])
	setZero(c.tmpkey[:])
	setZero(c.guardKey[:])
	_ = guardedmem.Free(c)
}

// generate a temporary key for cell randomization.
func (c *Cell) genTmpKey() {
	if _, err := io.ReadFull(rand.Reader, c.tmpkey[:]); err != nil {
		panic(err)
	}
}

// New returns a new Cell using at least size bytes to protect it.
func New(size int) (*Cell, error) {
	var err error
	var r *Cell
	r, err = guardedmem.Alloc(Cell{})
	if err != nil {
		return nil, err
	}
	r.size = size
	r.genTmpKey()
	if r.guard, err = allocGuard(size, &r.tmpkey); err != nil {
		r.guard.free()
		_ = guardedmem.Free(r)
		return nil, err
	}
	return r, nil
}

// return the hash of the guard pages.
func (c *Cell) hash() []byte {
	_ = c.guard.hash(c.guardKey[:])
	return c.guardKey[:]
}

// Store the secret d into the Cell. d needs to be KeySize bytes long.
func (c *Cell) Store(d []byte) {
	if len(d) != KeySize {
		panic("key has wrong size")
	}
	subtle.XORBytes(c.protectedSecret[:], c.hash(), d)
	setZero(c.guardKey[:])
}

// With executes f with the decrypted secret as a parameter.
func (c *Cell) With(f func([KeySize]byte) error) error {
	subtle.XORBytes(c.decryptedSecret[:], c.hash(), c.protectedSecret[:])
	defer func() {
		if err := recover(); err != nil {
			setZero(c.decryptedSecret[:])
			setZero(c.guardKey[:])
			panic(err)
		}
	}()
	err := f(c.decryptedSecret)
	setZero(c.decryptedSecret[:])
	setZero(c.guardKey[:])
	return err
}

// Update the cell with new random guard pages.
func (c *Cell) Update() error {
	var err error
	var tg *guard
	c.genTmpKey()
	if tg, err = allocGuard(c.size, &c.tmpkey); err != nil {
		if tg != nil {
			tg.free()
		}
		return err
	}
	tg.hash(c.rollKey[:])
	subtle.XORBytes(c.rollKey[:], c.rollKey[:], c.hash())
	subtle.XORBytes(c.protectedSecret[:], c.protectedSecret[:], c.rollKey[:])
	old := c.guard
	c.guard = tg
	old.free()
	return nil
}
