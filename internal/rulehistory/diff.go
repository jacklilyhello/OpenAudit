package rulehistory

import "strings"

func TextDiff(before, after string) Diff {
	a := split(before)
	b := split(after)
	ca := map[string]int{}
	cb := map[string]int{}
	for _, l := range a {
		ca[l]++
	}
	for _, l := range b {
		cb[l]++
	}
	d := Diff{Added: []string{}, Removed: []string{}}
	rem := map[string]int{}
	for k, v := range cb {
		rem[k] = v - ca[k]
		if rem[k] < 0 {
			rem[k] = 0
		}
	}
	for _, l := range b {
		if rem[l] > 0 {
			d.Added = append(d.Added, "+ "+l)
			rem[l]--
		}
	}
	rem = map[string]int{}
	for k, v := range ca {
		rem[k] = v - cb[k]
		if rem[k] < 0 {
			rem[k] = 0
		}
	}
	for _, l := range a {
		if rem[l] > 0 {
			d.Removed = append(d.Removed, "- "+l)
			rem[l]--
		}
	}
	d.Summary = DiffSummary{AddedLines: len(d.Added), RemovedLines: len(d.Removed)}
	return d
}
func split(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
