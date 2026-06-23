package matcher

import "errors"

const (
	RegexEngineRE2   = "re2"
	RegexEnginePCRE2 = "pcre2"
)

var ErrPCRE2Unsupported = errors.New("PCRE2 runtime support is not included in this build")

type RegexBackend interface {
	FindAllStringIndex(text string) [][]int
}

func PCRE2Available() bool                                     { return pcre2Available() }
func CompilePCRE2Pattern(pattern string) (RegexBackend, error) { return compilePCRE2Pattern(pattern) }
