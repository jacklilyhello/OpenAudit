//go:build !pcre2

package matcher

func pcre2Available() bool                                     { return false }
func compilePCRE2Pattern(pattern string) (RegexBackend, error) { return nil, ErrPCRE2Unsupported }
