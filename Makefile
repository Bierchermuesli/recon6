# Makefile for recon6 and recon4 (Go version)
# Makefile for recon6 and recon4 (Go version)
# Usage:
#   make recon6             → build default recon6 amd64 binary (dist/recon6)
#   make recon4             → build default recon4 amd64 binary (dist/recon4)
#   make armv7-recon6       → build recon6 ARMv7 binary
#   make armv7-recon4       → build recon4 ARMv7 binary
#   make arm64-recon6       → build recon6 ARM64 binary
#   make arm64-recon4       → build recon4 ARM64 binary
#   make windows-recon6     → build recon6 Windows binary (amd64)
#   make windows-recon4     → build recon4 Windows binary (amd64)
#   make all                → build all recon6 and recon4 targets
#   make clean              → remove dist directory

APP6    := recon6
APP4    := recon4
APP6    := recon6
APP4    := recon4

PROBE   ?= 0
ifeq ($(PROBE),0)
DIST    := dist
else
DIST    := dist/probe/$(PROBE)
endif

CAPS    := cap_net_raw,cap_net_admin=eip
GOFLAGS := -trimpath -ldflags="-s -w -X main.probe=$(PROBE)"
CGO     := 0

# Architectures
TARGETS := amd64 armv7 arm64

# Default build (amd64)
# By default, building recon6
default: recon6

# Build recon6 (amd64)
recon6: $(DIST)/$(APP6)
	@echo "✅ Build complete: $(DIST)/$(APP6)"
	@file $(DIST)/$(APP6)
# By default, building recon6
default: recon6

# Build recon6 (amd64)
recon6: $(DIST)/$(APP6)
	@echo "✅ Build complete: $(DIST)/$(APP6)"
	@file $(DIST)/$(APP6)
	@echo "Setting capabilities ($(CAPS))..."
	@sudo setcap $(CAPS) $(DIST)/$(APP6)
	@echo "Run it with: ./$(DIST)/$(APP6)"
	@sudo setcap $(CAPS) $(DIST)/$(APP6)
	@echo "Run it with: ./$(DIST)/$(APP6)"

$(DIST)/$(APP6): recon6.go
$(DIST)/$(APP6): recon6.go
	@mkdir -p $(DIST)
	@echo "🔧 Building static Go binary (linux/amd64) for $(APP6)..."
	@echo "🔧 Building static Go binary (linux/amd64) for $(APP6)..."
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=$(CGO) go build $(GOFLAGS) -o $@ recon6.go

# Build recon4 (amd64)
recon4: $(DIST)/$(APP4)
	@echo "✅ Build complete: $(DIST)/$(APP4)"
	@file $(DIST)/$(APP4)
	@echo "Setting capabilities ($(CAPS))..."
	@sudo setcap $(CAPS) $(DIST)/$(APP4)
	@echo "Run it with: ./$(DIST)/$(APP4)"

$(DIST)/$(APP4): recon4.go
	@mkdir -p $(DIST)
	@echo "🔧 Building static Go binary (linux/amd64) for $(APP4)..."
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=$(CGO) go build $(GOFLAGS) -o $@ recon4.go

# Build ARMv7 (32-bit) for recon6
armv7-recon6: recon6.go
	@mkdir -p $(DIST)
	@echo "🔧 Building Go binary for linux/armv7 for $(APP6)..."
	@GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=$(CGO) go build $(GOFLAGS) -o $(DIST)/$(APP6)-armv7 recon6.go
	@file $(DIST)/$(APP6)-armv7
	@echo "✅ Built: $(DIST)/$(APP6)-armv7"

# Build ARMv7 (32-bit) for recon4
armv7-recon4: recon4.go
	@mkdir -p $(DIST)
	@echo "🔧 Building Go binary for linux/armv7 for $(APP4)..."
	@GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=$(CGO) go build $(GOFLAGS) -o $(DIST)/$(APP4)-armv7 recon4.go
	@file $(DIST)/$(APP4)-armv7
	@echo "✅ Built: $(DIST)/$(APP4)-armv7"

# Build ARM64 (AArch64) for recon6
arm64-recon6: recon6.go
	@mkdir -p $(DIST)
	@echo "🔧 Building Go binary for linux/arm64 for $(APP6)..."
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=$(CGO) go build $(GOFLAGS) -o $(DIST)/$(APP6)-arm64 recon6.go
	@file $(DIST)/$(APP6)-arm64
	@echo "✅ Built: $(DIST)/$(APP6)-arm64"

# Build ARM64 (AArch64) for recon4
arm64-recon4: recon4.go
	@mkdir -p $(DIST)
	@echo "🔧 Building Go binary for linux/arm64 for $(APP4)..."
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=$(CGO) go build $(GOFLAGS) -o $(DIST)/$(APP4)-arm64 recon4.go
	@file $(DIST)/$(APP4)-arm64
	@echo "✅ Built: $(DIST)/$(APP4)-arm64"

# Build Windows (amd64) for recon6
windows-recon6: recon6.go
	@mkdir -p $(DIST)
	@echo "🔧 Building Go binary for windows/amd64 for $(APP6)..."
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=$(CGO) go build $(GOFLAGS) -o $(DIST)/$(APP6).exe recon6.go
	@file $(DIST)/$(APP6).exe
	@echo "✅ Built: $(DIST)/$(APP6).exe"

# Build Windows (amd64) for recon4
windows-recon4: recon4.go
	@mkdir -p $(DIST)
	@echo "🔧 Building Go binary for windows/amd64 for $(APP4)..."
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=$(CGO) go build $(GOFLAGS) -o $(DIST)/$(APP4).exe recon4.go
	@file $(DIST)/$(APP4).exe
	@echo "✅ Built: $(DIST)/$(APP4).exe"

# Build all supported targets
all: recon6 recon4 armv7-recon6 armv7-recon4 arm64-recon6 arm64-recon4 windows-recon6 windows-recon4
	@echo "✅ All targets built successfully."

clean:
	@echo "🧹 Cleaning..."
	@rm -rf $(DIST)
	@echo "Done."

.PHONY: recon6 recon4 armv7-recon6 armv7-recon4 arm64-recon6 arm64-recon4 windows-recon6 windows-recon4 all clean