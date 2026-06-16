package ai

import "context"

type CheckResult struct {
	Matched   bool
	Action    string
	RiskScore int
	Reason    string
}
type Checker interface {
	Check(ctx context.Context, text string) (CheckResult, error)
}
type NoopChecker struct{}

func (NoopChecker) Check(ctx context.Context, text string) (CheckResult, error) {
	return CheckResult{}, nil
}
