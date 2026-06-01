all: flagchecker.enc runner

%.elf: %.c link.ls
	gcc -Wall -Wextra -std=gnu2x -Os -fpie -static-pie -ffreestanding -nodefaultlibs -nostartfiles -fwhole-program -fno-stack-protector -T link.ls $< -o $@

%.bin: %.elf
	objcopy -j .out -O binary --strip-all $< $@

%.enc: %.bin key encrypt.py
	python3 encrypt.py $< $@

runner: runner.c
	gcc -Wall -Wextra -Os -fpie -static-pie -nodefaultlibs -nostartfiles -fno-stack-protector -fno-asynchronous-unwind-tables -maes $^ -o $@

.PHONY: all
