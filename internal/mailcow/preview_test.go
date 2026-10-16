package mailcow

import (
	"encoding/base64"
	"strings"
	"testing"
)

const phish = "From: =?UTF-8?B?UGF5UGFsIEJpbGxpbmc=?= <billing@paypa1-secure.example>\r\n" +
	"To: alice@example.org\r\n" +
	"Subject: =?UTF-8?Q?Your_account_is_on_hold?=\r\n" +
	"Authentication-Results: mx.example.org; spf=fail\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n" +
	"--outer\r\n" +
	"Content-Type: multipart/alternative; boundary=\"inner\"\r\n\r\n" +
	"--inner\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
	"Dear customer,=0AVerify your account caf=C3=A9 now.\r\n" +
	"--inner\r\n" +
	"Content-Type: text/html; charset=utf-8\r\n\r\n" +
	"<html><head><style>p{color:red}</style><script>alert(1)</script></head><body>" +
	"<p>Please <a href=\"https://login.paypa1-secure.example/verify\">https://www.paypal.com/signin</a></p>" +
	"<p><a href=\"https://www.example.org/help\">example.org/help</a> <a href=\"mailto:x@y.z\">mail us</a> <a href=\"javascript:alert(1)\">js</a></p>" +
	"</body></html>\r\n" +
	"--inner--\r\n" +
	"--outer\r\n" +
	"Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\n" +
	"Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n" +
	"Content-Transfer-Encoding: base64\r\n\r\n" +
	"TVpmYWtlLWJp\r\nbmFyeQ==\r\n" +
	"--outer--\r\n"

func TestPreviewMultipart(t *testing.T) {
	p := previewMessage(phish)
	if p.Error != "" {
		t.Fatalf("unexpected error %q", p.Error)
	}
	if got := p.Headers["From"]; got != "PayPal Billing <billing@paypa1-secure.example>" {
		t.Errorf("From header not decoded: %q", got)
	}
	if got := p.Headers["Subject"]; got != "Your account is on hold" {
		t.Errorf("Subject not decoded: %q", got)
	}
	// the plain part wins, and quoted-printable is decoded
	if p.FromHTML || !strings.Contains(p.Text, "Verify your account café now.") {
		t.Errorf("plain text part not used or not decoded: fromHTML=%v text=%q", p.FromHTML, p.Text)
	}
	if len(p.Attachments) != 1 || p.Attachments[0].Name != "invoice.pdf.exe" || p.Attachments[0].Size != len("MZfake-binary") {
		t.Errorf("attachment wrong: %+v", p.Attachments)
	}
}

func TestPreviewLinks(t *testing.T) {
	p := previewMessage(phish)
	if len(p.Links) != 2 {
		t.Fatalf("want 2 web links (mailto and javascript dropped), got %+v", p.Links)
	}
	disguised, honest := p.Links[0], p.Links[1]
	if !disguised.Mismatch || disguised.Host != "login.paypa1-secure.example" {
		t.Errorf("disguised link not flagged: %+v", disguised)
	}
	if honest.Mismatch {
		t.Errorf("www.example.org shown as example.org/help must not be flagged: %+v", honest)
	}
}

func TestPreviewHTMLOnly(t *testing.T) {
	raw := "Subject: hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" +
		"<html><head><title>T</title><style>.x{}</style></head><body><script>steal()</script><p>Hello&nbsp;there</p><p>Bye</p></body></html>"
	p := previewMessage(raw)
	if !p.FromHTML {
		t.Fatal("expected text converted from HTML")
	}
	if strings.Contains(p.Text, "steal") || strings.Contains(p.Text, ".x{}") || strings.Contains(p.Text, "<") {
		t.Errorf("script, style or markup leaked into the text: %q", p.Text)
	}
	if !strings.Contains(p.Text, "Hello there") || !strings.Contains(p.Text, "Bye") {
		t.Errorf("readable text missing: %q", p.Text)
	}
}

func TestPreviewLatin1AndBase64Body(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte("Gr\xfc\xdfe aus K\xf6ln"))
	raw := "Subject: x\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: base64\r\n\r\n" + body + "\r\n"
	p := previewMessage(raw)
	if !strings.Contains(p.Text, "Grüße aus Köln") {
		t.Errorf("latin-1 base64 body not decoded: %q", p.Text)
	}
}

func TestPreviewLimits(t *testing.T) {
	if p := previewMessage(""); p.Error == "" {
		t.Error("empty message should report that no copy was kept")
	}
	raw := "Subject: big\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("a", previewTextLimit+500)
	p := previewMessage(raw)
	if !p.Truncated || len(p.Text) != previewTextLimit {
		t.Errorf("long text not truncated: truncated=%v len=%d", p.Truncated, len(p.Text))
	}
}

func TestSameSite(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"www.example.org", "example.org", true}, {"mail.example.org", "example.org", true}, {"example.org", "example.org.evil.test", false}, {"paypal.com", "paypa1.com", false}} {
		if got := sameSite(c.a, c.b); got != c.want {
			t.Errorf("sameSite(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
