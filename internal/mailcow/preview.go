package mailcow

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// MessagePreview is a safe summary of a quarantined message: decoded headers, the text
// (HTML is reduced to text, never passed on), the links it contains and its attachments.
type MessagePreview struct {
	Headers     map[string]string `json:"headers"`
	Text        string            `json:"text"`
	FromHTML    bool              `json:"from_html"`
	Links       []PreviewLink     `json:"links"`
	Attachments []PreviewFile     `json:"attachments"`
	Truncated   bool              `json:"truncated"`
	Error       string            `json:"error,omitempty"`
}

// PreviewLink is a link as shown to the reader and where it really goes.
type PreviewLink struct {
	Text     string `json:"text"`
	Href     string `json:"href"`
	Host     string `json:"host"`
	Mismatch bool   `json:"mismatch"` // the text looks like a different web address
}

// PreviewFile is an attachment's name, type and decoded size.
type PreviewFile struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int    `json:"size"`
}

const previewTextLimit = 20000

var previewHeaders = []string{"From", "Reply-To", "Return-Path", "To", "Cc", "Subject", "Date", "Message-ID",
	"Authentication-Results", "X-Mailer", "List-Unsubscribe"}

func previewMessage(raw string) MessagePreview {
	p := MessagePreview{Headers: map[string]string{}, Links: []PreviewLink{}, Attachments: []PreviewFile{}}
	if raw == "" {
		p.Error = "mailcow kept no copy of this message"
		return p
	}
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		p.Error = "the message could not be read"
		return p
	}
	dec := new(mime.WordDecoder)
	for _, h := range previewHeaders {
		if v := m.Header.Get(h); v != "" {
			if d, err := dec.DecodeHeader(v); err == nil {
				v = d
			}
			p.Headers[h] = clip(v, 1000)
		}
	}
	var plain, htmlText string
	walkPart(m.Header, m.Body, 0, &plain, &htmlText, &p)
	switch {
	case strings.TrimSpace(plain) != "":
		p.Text = plain
	case htmlText != "":
		p.Text, p.FromHTML = htmlText, true
	}
	if len(p.Text) > previewTextLimit {
		p.Text, p.Truncated = p.Text[:previewTextLimit], true
	}
	if len(p.Links) > 100 {
		p.Links, p.Truncated = p.Links[:100], true
	}
	return p
}

type headerGetter interface{ Get(string) string }

func walkPart(h headerGetter, body io.Reader, depth int, plain, htmlText *string, p *MessagePreview) {
	if depth > 8 {
		return
	}
	ct, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		ct = "text/plain"
	}
	if strings.HasPrefix(ct, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err != nil {
				return
			}
			walkPart(part.Header, part, depth+1, plain, htmlText, p)
		}
	}
	data, _ := io.ReadAll(io.LimitReader(decodeTransfer(h.Get("Content-Transfer-Encoding"), body), 8<<20))
	disp, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	name := dparams["filename"]
	if name == "" {
		name = params["name"]
	}
	if d, err := new(mime.WordDecoder).DecodeHeader(name); err == nil {
		name = d
	}
	if disp == "attachment" || name != "" || !(ct == "text/plain" || ct == "text/html") {
		if ct == "message/rfc822" && name == "" {
			name = "attached message"
		}
		p.Attachments = append(p.Attachments, PreviewFile{Name: clip(name, 200), Type: ct, Size: len(data)})
		return
	}
	text := toUTF8(data, params["charset"])
	if ct == "text/html" {
		if *htmlText == "" {
			*htmlText = htmlToText(text, p)
		}
		return
	}
	if *plain == "" {
		*plain = text
	}
}

func decodeTransfer(enc string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, &stripSpace{r: r})
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	}
	return r
}

// stripSpace drops line breaks so base64 bodies decode.
type stripSpace struct{ r io.Reader }

func (s *stripSpace) Read(b []byte) (int, error) {
	n, err := s.r.Read(b)
	j := 0
	for _, c := range b[:n] {
		if c != '\r' && c != '\n' && c != ' ' && c != '\t' {
			b[j] = c
			j++
		}
	}
	if j == 0 && err == nil && n > 0 {
		return s.Read(b)
	}
	return j, err
}

// toUTF8 handles UTF-8, ASCII and Latin-1/Windows-1252; anything else is shown with
// invalid bytes replaced.
func toUTF8(b []byte, charset string) string {
	cs := strings.ToLower(strings.TrimSpace(charset))
	if (cs == "iso-8859-1" || cs == "latin1" || cs == "windows-1252") && !utf8.Valid(b) {
		r := make([]rune, len(b))
		for i, c := range b {
			r[i] = rune(c)
		}
		return string(r)
	}
	return strings.ToValidUTF8(string(b), "�")
}

// htmlToText keeps the readable text of an HTML part and records its links.
func htmlToText(src string, p *MessagePreview) string {
	z := html.NewTokenizer(strings.NewReader(src))
	var out bytes.Buffer
	skip := 0
	var href string
	var linkText strings.Builder
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return collapse(out.String())
		case html.TextToken:
			if skip == 0 {
				t := string(z.Text())
				out.WriteString(t)
				if href != "" {
					linkText.WriteString(t)
				}
			}
		case html.StartTagToken, html.EndTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			if tag == "script" || tag == "style" || tag == "head" || tag == "title" {
				if tt == html.StartTagToken {
					skip++
				} else if tt == html.EndTagToken && skip > 0 {
					skip--
				}
				continue
			}
			switch tag {
			case "br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table", "blockquote":
				out.WriteByte('\n')
			case "a":
				if tt == html.StartTagToken && hasAttr {
					for {
						k, v, more := z.TagAttr()
						if string(k) == "href" {
							href = string(v)
						}
						if !more {
							break
						}
					}
					linkText.Reset()
				} else if tt == html.EndTagToken && href != "" {
					addLink(p, strings.TrimSpace(collapse(linkText.String())), href)
					href = ""
				}
			}
		}
	}
}

func addLink(p *MessagePreview, text, href string) {
	u, err := url.Parse(strings.TrimSpace(href))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return
	}
	l := PreviewLink{Text: clip(text, 200), Href: clip(u.String(), 500), Host: strings.ToLower(u.Hostname())}
	// a link whose text is itself a web address on another host is a classic phishing trick
	if t := strings.ToLower(strings.TrimSpace(text)); strings.Contains(t, ".") && !strings.Contains(t, " ") {
		if tu, err := url.Parse(map[bool]string{true: t, false: "https://" + t}[strings.HasPrefix(t, "http")]); err == nil && tu.Hostname() != "" &&
			strings.Contains(tu.Hostname(), ".") && !sameSite(tu.Hostname(), l.Host) {
			l.Mismatch = true
		}
	}
	p.Links = append(p.Links, l)
}

func sameSite(a, b string) bool {
	a, b = strings.TrimPrefix(a, "www."), strings.TrimPrefix(b, "www.")
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

func collapse(s string) string {
	lines := strings.Split(strings.ReplaceAll(html.UnescapeString(s), " ", " "), "\n")
	out := make([]string, 0, len(lines))
	blank := false
	for _, l := range lines {
		l = strings.Join(strings.Fields(l), " ")
		if l == "" {
			if !blank && len(out) > 0 {
				out = append(out, "")
			}
			blank = true
			continue
		}
		blank = false
		out = append(out, l)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
