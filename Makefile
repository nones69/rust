# Target OS Compiler Setup
CC = x86_64-elf-gcc
AS = nasm
CFLAGS = -ffreestanding -mno-red-zone -Wall -Wextra -pedantic -std=c11 -O2
ASFLAGS = -f elf64

# Host Compiler Setup (for testing)
HOST_CC = gcc
HOST_CFLAGS = -Wall -Wextra -pedantic -std=c11 -O2

DEBUG_FLAGS = -g -DDEBUG
INCLUDES = -Isrc

# Main targets
all: kernel test_harness

KERNEL_OBJS = src/arch/x86_64/boot/boot.o src/kernel/console/console.o src/kernel/init/main.o

src/arch/x86_64/boot/boot.o: src/arch/x86_64/boot/boot.asm
	$(AS) $(ASFLAGS) -o $@ $<

src/kernel/init/main.o: src/kernel/init/main.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

src/kernel/console/console.o: src/kernel/console/console.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

kernel: $(KERNEL_OBJS)
	$(CC) -T src/arch/x86_64/linker.ld -o IntentKernel.bin -ffreestanding -O2 -nostdlib $(KERNEL_OBJS) -lgcc
	@echo "Kernel built successfully as IntentKernel.bin"

# Debug build
debug: HOST_CFLAGS += $(DEBUG_FLAGS)
debug: CFLAGS += $(DEBUG_FLAGS)
debug: test_harness

# Build the reference implementation
capability_core.o: src/reference/capability_core_modified.c src/reference/capability_core.h src/reference/secure_random.h
	$(HOST_CC) $(HOST_CFLAGS) $(INCLUDES) -c -o capability_core.o src/reference/capability_core_modified.c

secure_random.o: src/reference/secure_random.c src/reference/secure_random.h
	$(HOST_CC) $(HOST_CFLAGS) $(INCLUDES) -c -o secure_random.o src/reference/secure_random.c

# Build the test harness
test_harness: src/test_harness.c capability_core.o secure_random.o
	$(HOST_CC) $(HOST_CFLAGS) $(INCLUDES) -o test_harness src/test_harness.c capability_core.o secure_random.o -lrt

# Emulation
run: kernel
	qemu-system-x86_64 -m 512M -kernel IntentKernel.bin

# Clean build artifacts
clean:
	rm -f test_harness *.o *.elf *.bin *.iso src/arch/x86_64/boot/*.o src/kernel/init/*.o src/kernel/console/*.o

.PHONY: all debug clean kernel run