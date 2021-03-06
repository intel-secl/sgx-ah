GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: shub installer all test clean

shub:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/shub/version.BuildDate=$(BUILDDATE) -X intel/isecl/shub/version.Version=$(VERSION) -X intel/isecl/shub/version.GitHash=$(GITCOMMIT)" -o out/shub

swagger-get:
	wget https://github.com/go-swagger/go-swagger/releases/download/v0.21.0/swagger_linux_amd64 -O /usr/local/bin/swagger
	chmod +x /usr/local/bin/swagger
	wget https://repo1.maven.org/maven2/io/swagger/codegen/v3/swagger-codegen-cli/3.0.16/swagger-codegen-cli-3.0.16.jar -O /usr/local/bin/swagger-codegen-cli.jar
	
swagger-doc:
	mkdir -p out/swagger
	/usr/local/bin/swagger generate spec -o ./out/swagger/openapi.yml --scan-models
	java -jar /usr/local/bin/swagger-codegen-cli.jar generate -i ./out/swagger/openapi.yml -o ./out/swagger/ -l html2 -t ./swagger/templates/

swagger: swagger-get swagger-doc

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

all: clean installer

clean:
	rm -f cover.*
	rm -f shub
	rm -rf out/
