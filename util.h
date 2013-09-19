#pragma once

void _assert(int pred, const char *s);
void set_nonblocking(int fd);
void _dump_mem(const unsigned char* buf, size_t len);
void set_writable(void* addr, size_t len);
long get_sym_addr(char* path, char* sym);
size_t get_insn_size(char* path, long addr);

