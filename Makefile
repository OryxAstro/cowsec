# Build the CowSec binary, the web UI and a Debian/Ubuntu package (amd64).
# Versions always sort upwards for apt: v0.3.0 -> 0.3.0, 5 commits later -> 0.3.0+5.gabc1234,
# and before the first tag -> 0.3.0~dev+<commit count>.<hash> (sorts below 0.3.0).
BASE_VERSION := 0.3.0
GIT_DESC := $(shell git describe --tags --long --match 'v[0-9]*' 2>/dev/null)
GIT_DIRTY := $(shell git diff --quiet HEAD 2>/dev/null || echo .dirty)
ifneq ($(GIT_DESC),)
GIT_VERSION := $(shell echo $(GIT_DESC) | sed -E 's/^v//; s/-0-g[0-9a-f]+$$//; s/-([0-9]+)-(g[0-9a-f]+)$$/+\1.\2/')$(GIT_DIRTY)
else
GIT_VERSION := $(BASE_VERSION)~dev+$(shell git rev-list --count HEAD 2>/dev/null).$(shell git rev-parse --short HEAD 2>/dev/null)$(GIT_DIRTY)
endif
VERSION ?= $(GIT_VERSION)
DEB_VERSION := $(shell echo $(VERSION) | sed 's/-/~/g')
BUILD := build
PKG := $(BUILD)/pkg

.PHONY: all web bin deb test clean

all: deb

web:
	cd web && npm ci --no-audit --no-fund && npm run build

bin:
	mkdir -p $(BUILD)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD)/cowsec ./cmd/cowsec

test:
	go vet ./...
	go test ./...
	python3 -m py_compile packaging/lib/setup_engine.py packaging/lib/cowsec-hostctl packaging/cowsec-setup

deb: web bin test
	rm -rf $(PKG)
	install -D -m 0755 $(BUILD)/cowsec $(PKG)/usr/bin/cowsec
	install -D -m 0755 packaging/cowsec-setup $(PKG)/usr/sbin/cowsec-setup
	install -D -m 0755 packaging/lib/cowsec-hostctl $(PKG)/usr/lib/cowsec/cowsec-hostctl
	install -D -m 0644 packaging/lib/setup_engine.py $(PKG)/usr/lib/cowsec/setup_engine.py
	install -D -m 0644 packaging/cowsec.service $(PKG)/lib/systemd/system/cowsec.service
	mkdir -p $(PKG)/usr/share/cowsec/ui $(PKG)/usr/share/doc/cowsec $(PKG)/DEBIAN
	cp -r web/dist/. $(PKG)/usr/share/cowsec/ui/
	cp README.md $(PKG)/usr/share/doc/cowsec/
	sed 's/@VERSION@/$(DEB_VERSION)/' packaging/deb/control.in > $(PKG)/DEBIAN/control
	install -m 0755 packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm $(PKG)/DEBIAN/
	find $(PKG) -name __pycache__ -prune -exec rm -rf {} +
	dpkg-deb --root-owner-group --build $(PKG) $(BUILD)/cowsec_$(DEB_VERSION)_amd64.deb
	cd $(BUILD) && sha256sum cowsec_*_amd64.deb > SHA256SUMS
	@echo "built $(BUILD)/cowsec_$(DEB_VERSION)_amd64.deb"

clean:
	rm -rf $(BUILD) web/dist
