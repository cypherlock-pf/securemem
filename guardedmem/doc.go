// Package guardedmem implements memory allocations that are guarded against scanning. In addition, it
// supports storing keys in ballooned memory regions to make memory scanning and side channel attacks harder.
// It allocates at least three pages like this:  |PROT_NONE|PROT_READ,PROT_WRITE|...|PROT_NONE|
package guardedmem
