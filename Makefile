GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
#GITCOMMIT := $(shell git describe --always)
GITCOMMIT := e991de2 
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)

.PHONY: sgx-attestation-hub installer docker all test clean

sgx-attestation-hub:
	env GOOS=linux go build -ldflags "-X intel/isecl/sgx-attestation-hub/version.Version=$(VERSION) -X intel/isecl/sgx-attestation-hub/version.GitHash=$(GITCOMMIT)" -o out/sgx-attestation-hub

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html


installer: sgx-attestation-hub
	mkdir -p out/installer
	cp dist/linux/sgx-attestation-hub.service out/installer/sgx-attestation-hub.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp dist/linux/db_rotation.sql out/installer/db_rotation.sql
	cp out/sgx-attestation-hub out/installer/sgx-attestation-hub
	makeself out/installer out/sgx-attestation-hub-$(VERSION).bin "SGX Attestation Hub Service $(VERSION)" ./install.sh
	cp dist/linux/install_pgsahdb.sh out/install_pgsahdb.sh && chmod +x out/install_pgsahdb.sh

docker: installer
	cp dist/docker/entrypoint.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
	docker build -t isecl/sgx-attestation-hub:latest -f ./dist/docker/Dockerfile ./out
	docker save isecl/sgx-attestation-hub:latest > ./out/docker-sgx-attestation-hub-$(VERSION)-$(GITCOMMIT).tar

docker-zip: installer
	mkdir -p out/docker-sgx-attestation-hub
	cp dist/docker/docker-compose.yml out/docker-sgx-attestation-hub/docker-compose
	cp dist/docker/entrypoint.sh out/docker-sgx-attestation-hub/entrypoint.sh && chmod +x out/docker-sgx-attestation-hub/entrypoint.sh
	cp dist/docker/README.md out/docker-sgx-attestation-hub/README.md
	cp out/sgx-attestation-hub-$(VERSION).bin out/docker-sgx-attestation-hub/sgx-attestation-hub-$(VERSION).bin
	cp dist/docker/Dockerfile out/docker-sgx-attestation-hub/Dockerfile
	zip -r out/docker-sgx-attestation-hub.zip out/docker-sgx-attestation-hub	

all: test docker

clean:
	rm -f cover.*
	rm -f sgx-attestation-hub
	rm -rf out/
