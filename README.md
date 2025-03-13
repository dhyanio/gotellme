```sh
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -c trace_execve.c -o trace_execve.o
```
```sh
go build -o trace_execve main.go
```

```sh
sudo ./trace_execve
```