CFLAGS = -Wall -Wextra -Werror -O1

.PHONY : all
all : payload.img

payload.o: payload.c
	$(CC) $(CFLAGS) -m64 -ffreestanding -fno-pic -c -o $@ $^

payload.img: payload.o
	$(LD) -T payload.ld $^ -o $@

.PHONY: clean
clean:
	$(RM) payload.o payload.img
