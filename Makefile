GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: shub installer docker all test clean

shub:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/shub/version.BuildDate=$(BUILDDATE) -X intel/isecl/shub/version.Version=$(VERSION) -X intel/isecl/shub/version.GitHash=$(GITCOMMIT)" -o out/shub

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html


installer: shub
	mkdir -p out/installer
	cp dist/linux/shub.service out/installer/shub.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp dist/linux/db_rotation.sql out/installer/db_rotation.sql
	cp out/shub out/installer/shub
	makeself out/installer out/shub-$(VERSION).bin "SGX Attestation Hub Service $(VERSION)" ./install.sh
	cp dist/linux/install_pgshubdb.sh out/install_pgshubdb.sh && chmod +x out/install_pgshubdb.sh

docker: installer
	cp dist/docker/entrypoint.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
	docker build -t isecl/shub:latest -f ./dist/docker/Dockerfile ./out
	docker save isecl/shub:latest > ./out/docker-shub-$(VERSION)-$(GITCOMMIT).tar

docker-zip: installer
	mkdir -p out/docker-shub
	cp dist/docker/docker-compose.yml out/docker-shub/docker-compose
	cp dist/docker/entrypoint.sh out/docker-shub/entrypoint.sh && chmod +x out/docker-shub/entrypoint.sh
	cp dist/docker/README.md out/docker-shub/README.md
	cp out/shub-$(VERSION).bin out/docker-shub/shub-$(VERSION).bin
	cp dist/docker/Dockerfile out/docker-shub/Dockerfile
	zip -r out/docker-shub.zip out/docker-shub

all: test docker

clean:
	rm -f cover.*
	rm -f shub
	rm -rf out/
