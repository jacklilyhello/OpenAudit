//go:build pcre2

package matcher

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <stdlib.h>
#include <string.h>
#include <pcre2.h>

static pcre2_compile_context *oa_compile_context() { return pcre2_compile_context_create(NULL); }
static pcre2_match_context *oa_match_context() {
    pcre2_match_context *ctx = pcre2_match_context_create(NULL);
    if (ctx != NULL) {
        pcre2_set_match_limit(ctx, 100000);
        pcre2_set_depth_limit(ctx, 10000);
    }
    return ctx;
}
*/
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

type pcre2Pattern struct {
	code *C.pcre2_code
	mctx *C.pcre2_match_context
}

func pcre2Available() bool { return true }

func compilePCRE2Pattern(pattern string) (RegexBackend, error) {
	cpat := C.CBytes([]byte(pattern))
	defer C.free(cpat)
	var errnum C.int
	var erroff C.PCRE2_SIZE
	cctx := C.oa_compile_context()
	if cctx != nil {
		defer C.pcre2_compile_context_free(cctx)
	}
	code := C.pcre2_compile((*C.PCRE2_UCHAR)(cpat), C.PCRE2_SIZE(len(pattern)), C.PCRE2_UTF|C.PCRE2_UCP, &errnum, &erroff, cctx)
	if code == nil {
		return nil, fmt.Errorf("invalid PCRE2 regex at byte offset %d: error code %d", uint64(erroff), int(errnum))
	}
	p := &pcre2Pattern{code: code, mctx: C.oa_match_context()}
	if p.mctx == nil {
		C.pcre2_code_free(code)
		return nil, errors.New("create PCRE2 match context")
	}
	runtime.SetFinalizer(p, (*pcre2Pattern).close)
	return p, nil
}

func (p *pcre2Pattern) close() {
	if p.mctx != nil {
		C.pcre2_match_context_free(p.mctx)
		p.mctx = nil
	}
	if p.code != nil {
		C.pcre2_code_free(p.code)
		p.code = nil
	}
}

func (p *pcre2Pattern) FindAllStringIndex(text string) [][]int {
	if p == nil || p.code == nil {
		return nil
	}
	input := C.CBytes([]byte(text))
	defer C.free(input)
	md := C.pcre2_match_data_create_from_pattern(p.code, nil)
	if md == nil {
		return nil
	}
	defer C.pcre2_match_data_free(md)
	var out [][]int
	offset := C.PCRE2_SIZE(0)
	length := C.PCRE2_SIZE(len(text))
	for offset <= length {
		rc := C.pcre2_match(p.code, (*C.PCRE2_UCHAR)(input), length, offset, 0, md, p.mctx)
		if rc < 0 {
			break
		}
		ovec := C.pcre2_get_ovector_pointer(md)
		start := int(*(*C.PCRE2_SIZE)(unsafe.Pointer(uintptr(unsafe.Pointer(ovec)))))
		end := int(*(*C.PCRE2_SIZE)(unsafe.Pointer(uintptr(unsafe.Pointer(ovec)) + unsafe.Sizeof(C.PCRE2_SIZE(0)))))
		out = append(out, []int{start, end})
		if end == start {
			offset = C.PCRE2_SIZE(end + 1)
		} else {
			offset = C.PCRE2_SIZE(end)
		}
	}
	return out
}
