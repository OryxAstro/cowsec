// Package geo resolves IP addresses to country, city and network owner using the
// GeoLite2 databases CrowdSec already keeps on the host. Nothing leaves the machine.
package geo

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Info is the location of one IP address.
type Info struct {
	Query       string `json:"query"`
	Status      string `json:"status"` // success | fail
	CountryCode string `json:"countryCode"`
	Country     string `json:"country"`
	City        string `json:"city"`
	AS          string `json:"as"`
	Org         string `json:"org"`
	IsLAN       bool   `json:"isLan"`
}

// DB reads GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from dir, reopening them when
// CrowdSec refreshes the files.
type DB struct {
	dir string

	mu       sync.Mutex
	city     *maxminddb.Reader
	asn      *maxminddb.Reader
	cityTime time.Time
	asnTime  time.Time
	checked  time.Time
}

func New(dir string) *DB { return &DB{dir: dir} }

func (d *DB) open(name string, cur *maxminddb.Reader, curTime time.Time) (*maxminddb.Reader, time.Time) {
	path := filepath.Join(d.dir, name)
	st, err := os.Stat(path)
	if err != nil {
		return cur, curTime
	}
	if cur != nil && !st.ModTime().After(curTime) {
		return cur, curTime
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return cur, curTime
	}
	if cur != nil {
		cur.Close()
	}
	return r, st.ModTime()
}

func (d *DB) readers() (*maxminddb.Reader, *maxminddb.Reader) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.city == nil || d.asn == nil || time.Since(d.checked) > 10*time.Minute {
		d.city, d.cityTime = d.open("GeoLite2-City.mmdb", d.city, d.cityTime)
		d.asn, d.asnTime = d.open("GeoLite2-ASN.mmdb", d.asn, d.asnTime)
		d.checked = time.Now()
	}
	return d.city, d.asn
}

// Available reports whether the country database could be opened.
func (d *DB) Available() bool {
	city, _ := d.readers()
	return city != nil
}

var cgNAT = func() *net.IPNet { _, n, _ := net.ParseCIDR("100.64.0.0/10"); return n }()

// IsPrivate reports loopback, RFC1918/ULA, link-local and carrier-grade NAT addresses
// (an IP or the network address of a CIDR).
func IsPrivate(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		var err error
		if ip, _, err = net.ParseCIDR(s); err != nil {
			return false
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || cgNAT.Contains(ip)
}

type cityRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

type asnRecord struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// One looks up a single IP (or the network address of a CIDR).
func (d *DB) One(s string) *Info {
	info := &Info{Query: s, Status: "fail"}
	if IsPrivate(s) {
		info.Status, info.CountryCode, info.Country, info.IsLAN = "success", "LAN", "Local network", true
		info.City, info.AS, info.Org = "Private address", "Private range", "Local network"
		return info
	}
	ip := net.ParseIP(s)
	if ip == nil {
		if p, _, err := net.ParseCIDR(s); err == nil {
			ip = p
		} else {
			return info
		}
	}
	city, asn := d.readers()
	if city != nil {
		var rec cityRecord
		if city.Lookup(ip, &rec) == nil && rec.Country.ISOCode != "" {
			info.Status = "success"
			info.CountryCode, info.Country, info.City = rec.Country.ISOCode, rec.Country.Names["en"], rec.City.Names["en"]
		}
	}
	if asn != nil {
		var rec asnRecord
		if asn.Lookup(ip, &rec) == nil && rec.Number != 0 {
			info.AS = "AS" + itoa(rec.Number) + " " + rec.Org
			info.Org = rec.Org
		}
	}
	return info
}

// Lookup resolves many IPs at once.
func (d *DB) Lookup(ips []string) map[string]*Info {
	out := make(map[string]*Info, len(ips))
	for _, ip := range ips {
		if _, ok := out[ip]; !ok && ip != "" {
			out[ip] = d.One(ip)
		}
	}
	return out
}

// Country returns the ISO code and English name ("LAN" for private addresses, "??" if unknown).
func (d *DB) Country(ip string) (string, string) {
	i := d.One(ip)
	if i.Status != "success" {
		return "??", "Unknown"
	}
	return i.CountryCode, i.Country
}

func itoa(n uint) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
