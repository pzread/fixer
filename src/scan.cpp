#include "libcgcef/libcgcef.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    cgcef_version(EV_CURRENT);

    int fd;
    struct stat st;
    uint8_t *map;
    CGCEf *cgcef;

    if((fd = open(argv[1], O_RDONLY | O_CLOEXEC)) < 0) {
        return -1;
    }
    if(fstat(fd, &st)) {
        return -1;
    }
    if(!(map = (uint8_t*)mmap(
            NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0))) {
        return -1;
    }
    if(!(cgcef = cgcef_memory((char*)map, st.st_size))) {
        return -1;
    }

    CGCEf32_Ehdr *ehdr = cgcef32_getehdr(cgcef);
    printf("%u\n", ehdr->e_entry);

    // Find start address.
    CGCEf32_Phdr *phdr = cgcef32_getphdr(cgcef);
    size_t start_off = (st.st_size + 0xFFF) & ~0xFFF;
    size_t start_addr = 0;

    for(size_t i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
        if(phdr->p_type == PT_LOAD) {
            printf("%u %u %u\n", phdr->p_offset, phdr->p_vaddr, phdr->p_filesz);
            if((phdr->p_vaddr + phdr->p_memsz) > start_addr) {
                start_addr = phdr->p_vaddr + phdr->p_memsz;
            }
        }
    }
    printf("\n");
    start_addr = (start_addr + 0xFFF) & ~0xFFF;
    printf("%lu %lu %lu\n", start_off, start_addr, ~0UL);

    /*
    size_t phdrnum;
    if(cgcef_getphdrnum(cgcef, &phdrnum)) {
        return -1;
    }
    size_t x_off, x_addr, x_size = 0;
    for(; phdrnum > 0; --phdrnum, ++phdr) {
        if(phdr->p_type == PT_LOAD) {
            printf("%08x %08x %08x %08x\n", phdr->p_offset, phdr->p_vaddr,
                    phdr->p_filesz, phdr->p_memsz);
            if(phdr->p_flags & PF_X) {
                size_t addr = phdr->p_vaddr + phdr->p_memsz;
                size_t size = 0x1000 - (addr & 0xFFF);
                if(size > x_size) {
                    x_off = phdr->p_offset + phdr->p_memsz;
                    x_addr = phdr->p_vaddr + phdr->p_memsz;
                    x_size = size;
                }
            }
        }
    }
    */

    cgcef_end(cgcef);
    munmap(map, st.st_size);
    close(fd);
    return 0;
}
