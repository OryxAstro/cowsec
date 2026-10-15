# Build the CowSec binary, the web UI and a Debian/Ubuntu package (amd64).
GIT_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
VERSION ?= $(if $(GIT_VERSION),$(GIT_VERSION),0.0.0)
DEB_VERSION := $(shell echo $(VERSION) | sed 's/-/~/g; s/^[^0-9]/0~&/')
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
