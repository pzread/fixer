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

int create_phdr(size_t off, size_t addr, size_t size, unsigned int flags,
        CGCEf32_Phdr *phdr_entry) {
    phdr_entry->p_type = PT_LOAD;
    phdr_entry->p_offset = off;
    phdr_entry->p_vaddr = addr;
    phdr_entry->p_paddr = addr;
    phdr_entry->p_filesz = size;
    phdr_entry->p_memsz = size;
    phdr_entry->p_flags = flags;
    phdr_entry->p_align = 0x1000;
    return 0;
}

size_t copy_payload(int nfd, const char *path, size_t off) {
    int pfd;
    size_t retlen;
    size_t paylen = 0;
    char buf[4096];

    if((pfd = open(path, O_RDONLY | O_CLOEXEC)) < 0) {
        return -1;
    }
    lseek(nfd, off, SEEK_SET);
    while((retlen = read(pfd, buf, sizeof(buf))) > 0) {
        write(nfd, buf, retlen);
        paylen += retlen;
    }
    close(pfd);
    return paylen;
}

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
    int nfd = open(argv[2], O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0755);
    if(nfd < 0) {
        return -1;
    }
    lseek(nfd, 0, SEEK_SET); 
    if(write(nfd, map, st.st_size) != st.st_size) {
        return -1;
    }

    size_t text_off = strtoul(argv[4], NULL, 10);
    size_t text_addr = strtoul(argv[5], NULL, 10);
    size_t text_size = copy_payload(nfd, argv[3], text_off);

    CGCEf32_Phdr *phdr, phdr_entry;
    size_t phentsize = ehdr->e_phentsize;
    
    // Try to do inner append.
    bool appended = false;
    phdr = cgcef32_getphdr(cgcef);

    for(size_t i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
        if(phdr->p_type == PT_LOAD) {
            if(text_addr != phdr->p_vaddr + phdr->p_memsz) {
                continue;
            }
            if(phdr->p_flags != (PF_X | PF_R)) {
                continue;
            }
            if(phdr->p_filesz != phdr->p_memsz) {
                continue;
            }
            
            memcpy(&phdr_entry, phdr, sizeof(phdr_entry));
            phdr_entry.p_filesz += text_size;
            phdr_entry.p_memsz += text_size;
            lseek(nfd, ehdr->e_phoff + i * phentsize, SEEK_SET);
            write(nfd, &phdr_entry, phentsize);

            appended = true;
            break;
        }
    }
    if(!appended) {
        // Calculate address and size.
        size_t phdr_off = ((text_off + text_size) + 0x3) & ~0x3;
        size_t phdr_addr = ((text_addr + text_size) + 0x3) & ~0x3;
        size_t new_phdr_size = (ehdr->e_phnum + 1) * phentsize;

        // Create PHDR.
        lseek(nfd, phdr_off, SEEK_SET);
        write(nfd, map + ehdr->e_phoff, phentsize * ehdr->e_phnum);
        create_phdr(text_off, text_addr,
                (phdr_addr - text_addr) + new_phdr_size,
                PF_X | PF_R, &phdr_entry);
        write(nfd, &phdr_entry, phentsize);

        // Fix PHDR.
        phdr = cgcef32_getphdr(cgcef);
        for(size_t i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
            if(phdr->p_type == PT_PHDR) {
                memcpy(&phdr_entry, phdr, sizeof(phdr_entry));
                phdr_entry.p_offset = phdr_off;
                phdr_entry.p_vaddr = phdr_addr;
                phdr_entry.p_paddr = phdr_addr;
                phdr_entry.p_filesz += phentsize * 1;
                phdr_entry.p_memsz += phentsize * 1;

                lseek(nfd, ehdr->e_phoff + i * phentsize, SEEK_SET);
                write(nfd, &phdr_entry, phentsize);
                lseek(nfd, phdr_off + i * phentsize, SEEK_SET);
                write(nfd, &phdr_entry, phentsize);
            }
        }

        // Fix EHDR.
        CGCEf32_Ehdr ehdr_entry;
        memcpy(&ehdr_entry, ehdr, sizeof(ehdr_entry));
        ehdr_entry.e_phoff = phdr_off;
        ehdr_entry.e_phnum += 1;
        lseek(nfd, 0, SEEK_SET);
        write(nfd, &ehdr_entry, sizeof(ehdr_entry));
    }

    cgcef_end(cgcef);
    munmap(map, st.st_size);
    close(fd);
    close(nfd);
    return 0;
}
