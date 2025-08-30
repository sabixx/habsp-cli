BIN=habsp-cli
LDFLAGS=-s -w
BUILDVCS=-buildvcs=false

all: linux_amd64 windows_amd64 windows_arm64

linux_amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(BUILDVCS) -ldflags="$(LDFLAGS)" -o dist/$(BIN)-linux-amd64 .

linux_arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(BUILDVCS) -ldflags="$(LDFLAGS)" -o dist/$(BIN)-linux-arm64 .

windows_amd64:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(BUILDVCS) -ldflags="$(LDFLAGS)" -o dist/$(BIN)-windows-amd64.exe .

windows_arm64:
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build $(BUILDVCS) -ldflags="$(LDFLAGS)" -o dist/$(BIN)-windows-arm64.exe .
