package config

import "testing"

func TestReviewPolicyDefaultsAreReviewFirst(t *testing.T) {
	p := Defaults().ReviewPolicy
	if !p.Enabled || !p.AIReviewEnabled || !p.VariantReviewEnabled {
		t.Fatalf("review policy should be enabled for internal review routing: %#v", p)
	}
	if p.AllowAIHardBlock {
		t.Fatal("AI hard block must default false")
	}
	if p.UncertainDefaultAction != "temporary_allow" {
		t.Fatalf("unexpected default temporary action %q", p.UncertainDefaultAction)
	}
	if err := ValidateReviewPolicy(p); err != nil {
		t.Fatal(err)
	}
}

func TestReviewPolicyValidationRejectsInvalidThresholds(t *testing.T) {
	p := Defaults().ReviewPolicy
	p.AIScoreReviewThreshold = 1.2
	if err := ValidateReviewPolicy(p); err == nil {
		t.Fatal("expected invalid AI threshold")
	}
	p = Defaults().ReviewPolicy
	p.AIScoreTemporaryBlockThreshold = 0.5
	if err := ValidateReviewPolicy(p); err == nil {
		t.Fatal("expected temporary block threshold validation")
	}
	p = Defaults().ReviewPolicy
	p.UncertainDefaultAction = "reply_to_user"
	if err := ValidateReviewPolicy(p); err == nil {
		t.Fatal("expected invalid action validation")
	}
}
