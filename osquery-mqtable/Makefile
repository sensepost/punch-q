# ref: https://vic.demuzere.be/articles/golang-makefile-crosscompile/
LD_FLAGS := -s -w
BIN_DIR := build
BIN := mqtable.ext

default: clean darwin linux windows integrity

clean:
	$(RM) $(BIN_DIR)/$(BIN)*
	go clean -x

darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LD_FLAGS)" -o '$(BIN_DIR)/darwin-amd64-$(BIN)'

linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LD_FLAGS)" -o '$(BIN_DIR)/linux-amd64-$(BIN)'

windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LD_FLAGS)" -o '$(BIN_DIR)/windows-amd64-$(BIN)'

integrity:
	cd $(BIN_DIR) && shasum *
