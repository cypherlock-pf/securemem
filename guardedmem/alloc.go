package guardedmem

import (
	syscall "golang.org/x/sys/unix"
	"unsafe"
)

// allocSlize allocates size bytes of memory that is surrounded by guard pages.
// Tested.
func allocSlize(size int) (root, data []byte, err error) {
	pagesize := syscall.Getpagesize()
	if size%pagesize != 0 {
		size = (size/pagesize + 1) * pagesize
	}
	if root, err = syscall.Mmap(0, 0, pagesize*2+size, syscall.PROT_NONE, syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE|syscall.MAP_LOCKED); err != nil {
		return nil, nil, err
	}
	if err = syscall.Mprotect(root[pagesize:pagesize+size], syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		_ = syscall.Munmap(root)
		return nil, nil, err
	}
	return root, root[pagesize : pagesize+size], nil
}

// freeSlize frees the "root" memory returned by allocSlize.
// Tested.
func freeSlize(d []byte) error {
	return syscall.Munmap(d)
}

// Alloc allocates *T in guarded memory. Tested.
func Alloc[T any](a T) (alloc *T, err error) {
	size := unsafe.Sizeof(a)
	_, data, err := allocSlize(int(size))
	if err != nil {
		return nil, err
	}
	return (*T)(unsafe.Pointer(&data[0])), nil
}

// Free memory occupied by *T as previously created by  Alloc(T) *T. Tested.
func Free[T any](a *T) error {
	pagesize := syscall.Getpagesize()
	if a == nil {
		return nil
	}
	size := int(unsafe.Sizeof(*a))
	if size%pagesize != 0 {
		size = (size/pagesize + 1) * pagesize
	}

	start := (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(a)) - uintptr(pagesize)))
	return freeSlize(unsafe.Slice(start, size+2*pagesize))
}

// PageSize returns the size of a page.
func PageSize() int {
	return syscall.Getpagesize()
}
