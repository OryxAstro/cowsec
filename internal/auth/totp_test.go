package auth

import (
	"path/filepath"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA1 secret "12345678901234567890" (base32 below); 6-digit tail of the 8-digit vectors.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPRFC6238Vectors(t *testing.T) {
	for _, tc := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		got, err := totpCode(rfcSecret, tc.unix/totpPeriod)
		if err != nil || got != tc.want {
			t.Errorf("t=%d: got %q (%v), want %q", tc.unix, got, err, tc.want)
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	now := time.Unix(1234567890, 0)
	code, _ := totpCode(rfcSecret, now.Unix()/totpPeriod-1) // previous step, within skew
	if verifyTOTP(rfcSecret, code, now) < 0 {
		t.Fatal("code from previous step should be accepted")
	}
	old, _ := totpCode(rfcSecret, now.Unix()/totpPeriod-3)
	if verifyTOTP(rfcSecret, old, now) >= 0 {
		t.Fatal("code three steps old should be rejected")
	}

	st, err := OpenStore(filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetTOTP("alice", rfcSecret)
	c := verifyTOTP(rfcSecret, code, now)
	if !st.UseTOTPCounter("alice", c) {
		t.Fatal("first use should succeed")
	}
	if st.UseTOTPCounter("alice", c) {
		t.Fatal("replayed code must be rejected")
	}
}
