package guardedmem

import (
	_ "github.com/davecgh/go-spew/spew"
	"testing"
)

type PageContent struct {
	Next    *PageContent
	Content [100]byte
}

//
//func TestAlloc(t *testing.T) {
//	root, data, err := allocSlize(100)
//	if err != nil {
//		t.Fatalf("allocSlize: %s", err)
//	}
//	defer func() { _ = freeSlize(root) }()
//	t.Logf("Data size: %d (%d)", len(data), cap(data))
//	for i := 0; i < len(data); i++ {
//		data[i] = 0xff
//	}
//	//root[0]=0xff// This must cause SIGSEGV
//	//data = append(data, 0xff) // This must cause SIGSEGV
//}

func TestPointerStruct(t *testing.T) {
	x, err := Alloc(PageContent{})
	if err != nil {
		t.Errorf("Alloc: %s", err)
	}
	//_, _ = io.ReadFull(rand.Reader, x.Content[:])
	//spew.Dump(x)
	_ = Free(x)
}

func ExampleAlloc() {
	type X struct {
		a []byte
	}
	var x *X
	x, err := Alloc(X{})
	if err != nil {
		panic(err)
	}
	defer func() { _ = Free(x) }()

}
