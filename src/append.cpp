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

char buf[4096];

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

    // Clone binary.
    int nfd;
    if((nfd = open(argv[2],
            O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0755)) < 0) {
        return -1;
    }
    lseek(nfd, 0, SEEK_SET); 
    if(write(nfd, map, st.st_size) != st.st_size) {
        return -1;
    }

    size_t code_off = strtoul(argv[4], NULL, 10);
    size_t code_addr = strtoul(argv[5], NULL, 10);
    size_t code_size = 0;

    // Write payload
    int pfd;
    ssize_t retlen;
    if((pfd = open(argv[3], O_RDONLY | O_CLOEXEC)) < 0) {
        return -1;
    }
    lseek(nfd, code_off, SEEK_SET);
    while((retlen = read(pfd, buf, sizeof(buf))) > 0) {
        write(nfd, buf, retlen);   
        code_size += retlen;
    }
    close(pfd);

    // Calculate address and size.
    size_t phdr_off = code_off + code_size;
    size_t phdr_addr = code_addr + code_size;
    size_t append_size = code_size + (ehdr->e_phnum + 1) * ehdr->e_phentsize;

    // Copy PHDR.
    lseek(nfd, phdr_off, SEEK_SET);
    write(nfd, map + ehdr->e_phoff, ehdr->e_phentsize * ehdr->e_phnum);

    // Add PHDR.
    CGCEf32_Phdr phdr_entry;
    phdr_entry.p_type = PT_LOAD;
    phdr_entry.p_offset = code_off;
    phdr_entry.p_vaddr = code_addr;
    phdr_entry.p_paddr = code_addr;
    phdr_entry.p_filesz = append_size;
    phdr_entry.p_memsz = (append_size + 0xFFF) & ~0xFFF;
    phdr_entry.p_flags = PF_X | PF_R;
    phdr_entry.p_align = 0x1000;
    write(nfd, &phdr_entry, ehdr->e_phentsize);

    // Fix PHDR.
    CGCEf32_Phdr *phdr = cgcef32_getphdr(cgcef);
    for(size_t i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
        if(phdr->p_type == PT_PHDR) {
            memcpy(&phdr_entry, phdr, sizeof(phdr_entry));
            phdr_entry.p_offset = phdr_off;
            phdr_entry.p_vaddr = phdr_addr;
            phdr_entry.p_paddr = phdr_addr;
            phdr_entry.p_filesz += ehdr->e_phentsize * 1;
            phdr_entry.p_memsz += ehdr->e_phentsize * 1;
            lseek(nfd, ehdr->e_phoff + i * ehdr->e_phentsize, SEEK_SET);
            write(nfd, &phdr_entry, ehdr->e_phentsize);
            lseek(nfd, phdr_off + i * ehdr->e_phentsize, SEEK_SET);
            write(nfd, &phdr_entry, ehdr->e_phentsize);
        }
    }

    // Fix EHDR.
    CGCEf32_Ehdr ehdr_entry;
    memcpy(&ehdr_entry, ehdr, sizeof(ehdr_entry));
    ehdr_entry.e_phoff = phdr_off;
    ehdr_entry.e_phnum += 1;
    lseek(nfd, 0, SEEK_SET);
    write(nfd, &ehdr_entry, sizeof(ehdr_entry));

    cgcef_end(cgcef);
    munmap(map, st.st_size);
    close(fd);
    close(nfd);
    return 0;
}
