tools:
	BPF_CFLAGS='-D__TARGET_ARCH_x86' go generate ./cmd/execsnoop/
	BPF_CFLAGS='-D__TARGET_ARCH_x86' go generate ./cmd/kprobe/
	BPF_CFLAGS='-D__TARGET_ARCH_x86' go generate ./cmd/tcpconnect/
	BPF_CFLAGS='-D__TARGET_ARCH_x86' go generate ./cmd/tcpconnlat/
	BPF_CFLAGS='-D__TARGET_ARCH_x86' go generate ./cmd/tcplife/

build:
	docker build -t benbaker76/go-libbpf-tools:latest .

run:
	docker run --rm -it --privileged benbaker76/go-libbpf-tools:latest bash
