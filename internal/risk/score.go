package risk

func Score(level string, override int) int {
	if override > 0 {
		return override
	}
	switch level {
	case "high":
		return 90
	case "low":
		return 30
	default:
		return 60
	}
}
func HigherAction(a, b string) string {
	rank := map[string]int{"pass": 0, "review": 1, "block": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
