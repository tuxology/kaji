include ../Makefile.inc

CFLAGS += -I../include

all: libkaji.so client

libkaji.so: kaji.o trampoline.o
	gcc -ldl -lpthread -llttng-ust -shared $^ -o $@

kaji.o: kaji.c server.h kaji.h ust_kaji_test.h
	gcc -Wall -fPIC -I. -c $< -o $@

trampoline.o: trampoline.s
	gcc -fPIC -c $< -o $@

client.o: client.c
	gcc -Wall -I. -c $< -o $@

client: client.o
	gcc $^ -lbfd -ldl -ldistorm3 -liberty -lz -o $@

.PHONY: clean
clean:
	rm -f *.o libkaji.so client
