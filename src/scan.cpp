#include "libcgcef/libcgcef.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
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

    CGCEf32_Phdr *phdr = cgcef32_getphdr(cgcef);
    for(size_t i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
        if(phdr->p_type == PT_LOAD) {
            assert(phdr->p_align >= 0x1000 && "Small alignment.");
            printf("%u %u %u %u %d\n", phdr->p_offset, phdr->p_vaddr,
                    phdr->p_filesz, phdr->p_memsz,
                    (bool)(phdr->p_flags & PF_X));
        }
    }

    cgcef_end(cgcef);
    munmap(map, st.st_size);
    close(fd);
    return 0;
}
