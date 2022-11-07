.PHONY: generate
generate: main.go
	go generate ./...

.PHONY: build
build: bpf_bpfel.go bpf_bpfel.o
	go build -o bin/xs

.PHONY: all
all: generate build
