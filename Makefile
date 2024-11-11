APP=tc

.PHONY: $(APP)
$(APP): skel
	clang tc.c -Wno-unsequenced -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -c kernel_space.c -o kernel_space.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton kernel_space.o name tc > tc.skel.h


.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *.o *.skel.h vmlinux.h $(APP)