# Go libbpf-tools

An attempt to implement a Go frontend for
[libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools)
narrated in blog posts:

- [BPF: Go frontend for execsnoop](https://marselester.com/bpf-go-frontend-for-execsnoop.html)
- [BPF: Go frontend for tcpconnect](https://marselester.com/bpf-go-frontend-for-tcpconnect.html)
- [BPF Go program in Kubernetes](https://marselester.com/bpf-go-program-in-kubernetes.html)

Start a virtual machine, install Clang and Go.

```sh
$ vagrant up
$ vagrant ssh
$ sudo apt-get update
$ sudo apt-get install clang
$ sudo snap install go --classic
$ uname -nr
ubuntu-lunar 6.2.0-26-generic
$ clang -v
Ubuntu clang version 15.0.7
```

Compile C BPF program into BPF bytecode and generate Go files
with [bpf2go](https://github.com/cilium/ebpf/blob/master/cmd/bpf2go/doc.go) tool.

```sh
$ cd /vagrant/
$ BPF_CFLAGS='-D__TARGET_ARCH_x86' go generate ./cmd/tcpconnect/
$ sudo go run ./cmd/tcpconnect -timestamp -print-uid
TIME(s)  UID   PID    COMM         IP SADDR            DADDR            DPORT
0.000    1000  240332 curl         6  ::1              ::1              8000
3.079    1000  240334 curl         4  127.0.0.1        127.0.0.1        8000
```

Note, the headers were copied from the following sources.

```sh
$ git clone git://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/lunar
$ cp ./lunar/tools/lib/bpf/bpf_helpers.h ./headers/bpf
$ cp ./lunar/tools/lib/bpf/bpf_core_read.h ./headers/bpf
$ cp ./lunar/tools/lib/bpf/bpf_tracing.h ./headers/bpf
$ git clone https://github.com/libbpf/libbpf.git
$ cp ./libbpf/src/bpf_helper_defs.h ./headers/bpf
```

`vmlinux.h` was generated as follows.

```sh
$ sudo apt-get install linux-tools-common linux-tools-6.2.0-26-generic
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./headers/vmlinux.h
```
