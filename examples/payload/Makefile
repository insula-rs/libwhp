CFLAGS = -Wall -Wextra -Werror -O1
SFLAGS = -S -O1

.PHONY : all
all : payload.img

handler.o: handler.asm
	$(AS) -o $@ $<

payload.o: payload.c
	$(CC) $(CFLAGS) -m64 -ffreestanding -fno-pic -c -o $@ $^

helpers.o: helpers.c
	$(CC) $(CFLAGS) -m64 -ffreestanding -fno-pic -c -o $@ $^

payload.img: handler.o helpers.o payload.o
	$(LD) -T payload.ld $^ -o $@

.PHONY: clean
clean:
	$(RM) handler.o payload.o helpers.o payload.img
