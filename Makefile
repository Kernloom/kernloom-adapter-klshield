GO ?= go
TRIVY ?= trivy
COSIGN ?= cosign
GOVULNCHECK ?= govulncheck
DIST ?= dist
IMAGE ?=

BINARIES := kernloom-adapter-klshield

.PHONY: fmt vet test bpf-test build checksums sbom vuln-scan govulncheck release-provenance release-sign container-sign release-promote-check release-check

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

bpf-test:
	$(GO) test ./internal/adapter -run 'BPFMapRuntimeStore|BPFHealth'

build:
	mkdir -p bin
	$(GO) build -o bin/kernloom-adapter-klshield ./cmd/kernloom-adapter-klshield

checksums: build
	mkdir -p $(DIST)
	sha256sum $(addprefix bin/,$(BINARIES)) > $(DIST)/checksums.txt

release-provenance: checksums
	mkdir -p $(DIST)
	{ \
		echo "{"; \
		echo "  \"kind\": \"KernloomReleaseProvenance\","; \
		echo "  \"source_commit\": \"$$(git rev-parse HEAD)\","; \
		echo "  \"go_version\": \"$$($(GO) version)\","; \
		echo "  \"checksums\": \"$(DIST)/checksums.txt\""; \
		echo "}"; \
	} > $(DIST)/provenance.json

sbom: build
	@command -v $(TRIVY) >/dev/null 2>&1 || { echo "trivy is required for SBOM generation"; exit 127; }
	mkdir -p $(DIST)
	$(TRIVY) fs --format cyclonedx --output $(DIST)/sbom.cdx.json .

vuln-scan:
	@command -v $(TRIVY) >/dev/null 2>&1 || { echo "trivy is required for vulnerability scanning"; exit 127; }
	$(TRIVY) fs --exit-code 1 --severity HIGH,CRITICAL .

govulncheck:
	@command -v $(GOVULNCHECK) >/dev/null 2>&1 || { echo "govulncheck is required"; exit 127; }
	$(GOVULNCHECK) ./...

release-sign: checksums
	@command -v $(COSIGN) >/dev/null 2>&1 || { echo "cosign is required for release signing"; exit 127; }
	$(COSIGN) sign-blob --yes --output-signature $(DIST)/checksums.txt.sig $(DIST)/checksums.txt

container-sign:
	@test -n "$(IMAGE)" || { echo "IMAGE is required for container-sign"; exit 2; }
	@command -v $(COSIGN) >/dev/null 2>&1 || { echo "cosign is required for container signing"; exit 127; }
	$(COSIGN) sign --yes $(IMAGE)

release-promote-check: checksums sbom release-provenance
	test -s $(DIST)/checksums.txt
	test -s $(DIST)/sbom.cdx.json
	test -s $(DIST)/provenance.json

release-check: fmt vet test bpf-test build checksums sbom vuln-scan govulncheck release-provenance release-promote-check
