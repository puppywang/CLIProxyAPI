package auth

import (
	"context"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// Ported from upstream 5dcca50f (weighted round-robin scheduler + selector).

func TestWeightedRoundRobinSelectorPick_DistributesAndSkipsNonPositiveWeights(t *testing.T) {
	t.Parallel()

	selector := &WeightedRoundRobinSelector{}
	auths := []*Auth{
		{ID: "a", Attributes: map[string]string{AttributeWeight: "5"}},
		{ID: "b", Attributes: map[string]string{AttributeWeight: "3"}},
		{ID: "c", Attributes: map[string]string{AttributeWeight: "2"}},
		{ID: "disabled-by-weight", Attributes: map[string]string{AttributeWeight: "0"}},
	}

	counts := make(map[string]int)
	for index := 0; index < 100; index++ {
		got, errPick := selector.Pick(context.Background(), "gemini", "model", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("Pick() #%d error = %v", index, errPick)
		}
		counts[got.ID]++
	}
	want := map[string]int{"a": 50, "b": 30, "c": 20}
	for authID, wantCount := range want {
		if counts[authID] != wantCount {
			t.Fatalf("auth %q picks = %d, want %d", authID, counts[authID], wantCount)
		}
	}
	if counts["disabled-by-weight"] != 0 {
		t.Fatalf("non-positive weight auth picks = %d, want 0", counts["disabled-by-weight"])
	}
}

func TestWeightedRoundRobinSelectorPick_ResetsCreditsWhenWeightsChange(t *testing.T) {
	t.Parallel()

	selector := &WeightedRoundRobinSelector{}
	authA := &Auth{ID: "a", Attributes: map[string]string{AttributeWeight: "1000000"}}
	authB := &Auth{ID: "b", Attributes: map[string]string{AttributeWeight: "1"}}
	auths := []*Auth{authA, authB}
	for index := 0; index < 1000; index++ {
		if _, errPick := selector.Pick(context.Background(), "gemini", "model", cliproxyexecutor.Options{}, auths); errPick != nil {
			t.Fatalf("warmup Pick() #%d error = %v", index, errPick)
		}
	}

	authA.Attributes[AttributeWeight] = "1"
	counts := make(map[string]int)
	for index := 0; index < 20; index++ {
		got, errPick := selector.Pick(context.Background(), "gemini", "model", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("Pick() after weight change #%d error = %v", index, errPick)
		}
		counts[got.ID]++
	}
	if counts["a"] != 10 || counts["b"] != 10 {
		t.Fatalf("picks after weight change = %#v, want a:b=10:10", counts)
	}
}

func TestSchedulerPick_WeightedRoundRobin(t *testing.T) {
	t.Parallel()

	scheduler := newSchedulerForTest(
		&WeightedRoundRobinSelector{},
		&Auth{ID: "a", Provider: "gemini", Attributes: map[string]string{AttributeWeight: "5"}},
		&Auth{ID: "b", Provider: "gemini", Attributes: map[string]string{AttributeWeight: "3"}},
		&Auth{ID: "c", Provider: "gemini", Attributes: map[string]string{AttributeWeight: "2"}},
	)

	counts := make(map[string]int)
	for index := 0; index < 100; index++ {
		got, errPick := scheduler.pickSingle(context.Background(), "gemini", "", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("pickSingle() #%d error = %v", index, errPick)
		}
		counts[got.ID]++
	}
	want := map[string]int{"a": 50, "b": 30, "c": 20}
	for authID, wantCount := range want {
		if counts[authID] != wantCount {
			t.Fatalf("auth %q picks = %d, want %d", authID, counts[authID], wantCount)
		}
	}
}

func TestSchedulerPick_WeightedRoundRobinSkipsNonPositiveWeightPriorityTier(t *testing.T) {
	t.Parallel()

	scheduler := newSchedulerForTest(
		&WeightedRoundRobinSelector{},
		&Auth{ID: "excluded", Provider: "gemini", Attributes: map[string]string{"priority": "10", AttributeWeight: "0"}},
		&Auth{ID: "available", Provider: "gemini", Attributes: map[string]string{"priority": "0", AttributeWeight: "1"}},
	)
	got, errPick := scheduler.pickSingle(context.Background(), "gemini", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("pickSingle() error = %v", errPick)
	}
	if got == nil || got.ID != "available" {
		t.Fatalf("pickSingle() auth = %#v, want available", got)
	}
}

func TestSchedulerPick_WeightedRoundRobinResetsCreditsWhenWeightsChange(t *testing.T) {
	t.Parallel()

	authA := &Auth{ID: "a", Provider: "gemini", Attributes: map[string]string{AttributeWeight: "1000000"}}
	authB := &Auth{ID: "b", Provider: "gemini", Attributes: map[string]string{AttributeWeight: "1"}}
	scheduler := newSchedulerForTest(&WeightedRoundRobinSelector{}, authA, authB)
	for index := 0; index < 1000; index++ {
		if _, errPick := scheduler.pickSingle(context.Background(), "gemini", "", cliproxyexecutor.Options{}, nil); errPick != nil {
			t.Fatalf("warmup pickSingle() #%d error = %v", index, errPick)
		}
	}

	authA.Attributes[AttributeWeight] = "1"
	scheduler.upsertAuth(authA)
	counts := make(map[string]int)
	for index := 0; index < 20; index++ {
		got, errPick := scheduler.pickSingle(context.Background(), "gemini", "", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("pickSingle() after weight change #%d error = %v", index, errPick)
		}
		counts[got.ID]++
	}
	if counts["a"] != 10 || counts["b"] != 10 {
		t.Fatalf("picks after weight change = %#v, want a:b=10:10", counts)
	}
}

func TestSchedulerPick_MixedProvidersWeightedRoundRobin(t *testing.T) {
	t.Parallel()

	scheduler := newSchedulerForTest(
		&WeightedRoundRobinSelector{},
		&Auth{ID: "gemini-a", Provider: "gemini", Attributes: map[string]string{AttributeWeight: "5"}},
		&Auth{ID: "claude-b", Provider: "claude", Attributes: map[string]string{AttributeWeight: "3"}},
		&Auth{ID: "claude-c", Provider: "claude", Attributes: map[string]string{AttributeWeight: "2"}},
	)

	counts := make(map[string]int)
	for index := 0; index < 100; index++ {
		got, provider, errPick := scheduler.pickMixed(context.Background(), []string{"gemini", "claude"}, "", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("pickMixed() #%d error = %v", index, errPick)
		}
		if got == nil || provider == "" {
			t.Fatalf("pickMixed() #%d returned auth=%v provider=%q", index, got, provider)
		}
		counts[got.ID]++
	}
	want := map[string]int{"gemini-a": 50, "claude-b": 30, "claude-c": 20}
	for authID, wantCount := range want {
		if counts[authID] != wantCount {
			t.Fatalf("auth %q picks = %d, want %d", authID, counts[authID], wantCount)
		}
	}
}

func TestSchedulerPick_MixedProvidersResetsCreditsWhenWeightsChange(t *testing.T) {
	t.Parallel()

	authA := &Auth{ID: "gemini-a", Provider: "gemini", Attributes: map[string]string{AttributeWeight: "1000000"}}
	authB := &Auth{ID: "claude-b", Provider: "claude", Attributes: map[string]string{AttributeWeight: "1"}}
	scheduler := newSchedulerForTest(&WeightedRoundRobinSelector{}, authA, authB)
	providers := []string{"gemini", "claude"}
	for index := 0; index < 1000; index++ {
		if _, _, errPick := scheduler.pickMixed(context.Background(), providers, "", cliproxyexecutor.Options{}, nil); errPick != nil {
			t.Fatalf("warmup pickMixed() #%d error = %v", index, errPick)
		}
	}

	authA.Attributes[AttributeWeight] = "1"
	scheduler.upsertAuth(authA)
	counts := make(map[string]int)
	for index := 0; index < 20; index++ {
		got, _, errPick := scheduler.pickMixed(context.Background(), providers, "", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("pickMixed() after weight change #%d error = %v", index, errPick)
		}
		counts[got.ID]++
	}
	if counts[authA.ID] != 10 || counts[authB.ID] != 10 {
		t.Fatalf("mixed picks after weight change = %#v, want 10 each", counts)
	}
}
