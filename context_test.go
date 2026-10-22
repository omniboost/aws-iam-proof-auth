package iamproof

import (
	"context"
	"testing"
)

func TestPrincipalContextRoundTrip(t *testing.T) {
	want := &Principal{AccountID: "111", Role: "Reader", Session: "s", ARN: "assumed-role/Reader/s"}

	ctx := ContextWithPrincipal(context.Background(), want)
	got, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatal("expected principal in context")
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestPrincipalFromContext_Missing(t *testing.T) {
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Error("expected no principal in empty context")
	}
}
