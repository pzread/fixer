import argparse
import mmap
import re
import subprocess
import sys
import os
import tempfile
from capstone import *
from keystone import *


def scan(binpath):
    data = subprocess.check_output(['./bin/scan', binpath])
    data = data.decode('utf-8')
    lines = data.split('\n')
    entry, = lines[0].rstrip('\n').split(' ')
    entry = int(entry)
    lines = lines[1:]

    phlist = list()
    poslist = list()
    tail_off = 0
    tail_addr = 0
    for line in lines:
        line = line.rstrip('\n')
        if len(line) == 0:
            break

        off, addr, fsize, msize, is_x = line.split(' ')
        off = int(off)
        addr = int(addr)
        fsize = int(fsize)
        msize = int(msize)
        is_x = int(is_x)
        phlist.append((off, addr, fsize, msize))

        if (addr + msize) > tail_addr:
            tail_addr = addr + msize
        
        rel = msize & 0xFFF
        if is_x and rel < 0x1000 and msize == fsize:
            poslist.append((off + rel, addr + rel, 0x1000 - rel))

    tail_off = (os.stat(binpath).st_size + 0xFFF) & ~0xFFF
    tail_addr = (tail_addr + 0xFFF) & ~0xFFF
    poslist.append((tail_off, tail_addr, 256 ** 4))

    return entry, phlist, poslist


def vaddr_offset(phlist, vaddr):
    for off, addr, fsize, _ in phlist:
        if vaddr >= addr and vaddr < (addr + fsize):
            return off + (vaddr - addr)

    return None


def compile_payload(paypath, outpath):
    subprocess.check_output(['nasm', '-O0', '-f', 'elf', '-o',
            outpath, paypath])


def link_payload(elfpaths, text_addr, outpath, static=False):
    params = ['ld', '-m', 'elf_i386', '-T', './src/payload.lds',
            '--oformat', 'elf32-i386', '-Ttext=0x%x'%text_addr, '-o', outpath]
    if static:
        params += ['--static']
    else:
        params += ['--unresolved-symbols', 'ignore-all']
    subprocess.check_output(params + elfpaths)

    data = subprocess.check_output(['objdump', '-t', outpath])
    data = data.decode('utf-8')
    funclist = list()
    rx = re.compile('^([^\s]+)\s+g.*\s+([^\s]+)$')
    for line in data.split('\n'):
        line = line.rstrip('\n')
        result = rx.match(line)
        if result is not None:
            funclist.append((result.group(2), int(result.group(1), 16)))

    return funclist


def dump_binary(objpath, textpath):
    subprocess.check_output(['objcopy', '-O', 'binary', '-j', '.text',
            objpath, textpath])


def append(binpath, textpath, text_off, text_addr, outpath):
    subprocess.check_output(['./bin/append', binpath, outpath,
            textpath, str(text_off), str(text_addr)])


def get_patchpos(funclist):
    patchpos = list()
    for name, addr in funclist:
        if not name.startswith('patch_'):
            continue

        patchpos.append((name[len('patch_'):], addr))
    
    return patchpos


def main():
    opt = argparse.ArgumentParser(description='Fixer')
    opt.add_argument('binary', action='store', help='binary path')
    opt.add_argument('-p', dest='payload', action='store', default=None,
            help='payload path')
    opt.add_argument('-o', dest='output', action='store', default=None,
            help='output path')
    data = vars(opt.parse_args(sys.argv[1:]))
    binpath = data['binary']
    paypath = data['payload']
    outputpath = data['output']
    if outputpath is None:
        outputpath = binpath + '_patch'

    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    entry, phlist, poslist = scan(binpath)

    print('Offset Address Size')
    for (off, addr, size) in poslist:
        print('0x%08x 0x%08x %d'%(off, addr, size))

    if paypath is None:
        return

    payelf = tempfile.NamedTemporaryFile()
    compile_payload(paypath, payelf.name)
    with tempfile.NamedTemporaryFile() as tmpobj:
        funclist = link_payload([payelf.name], 0x0, tmpobj.name)

    patchpos = get_patchpos(funclist)

    binf = open(binpath, 'r+b')
    binm = mmap.mmap(binf.fileno(), 0)
    oricode = '[BITS 32]\nsection .backtext\n'
    jmpins_len = len(ks.asm('jmp 0x0')[0])
    patchmap = dict()
    for patch_token, _ in patchpos:
        patch_addr = int(patch_token, 16)
        patch_off = vaddr_offset(phlist, patch_addr)
        patch_len = 0

        oricode += 'global back_%s\nback_%s:\n'%(patch_token, patch_token)
        for ins in cs.disasm(binm[patch_off:], patch_addr):
            if ins.address - patch_addr >= jmpins_len:
                patch_len = ins.address - patch_addr
                oricode += 'jmp 0x%x\n'%ins.address
                break

            oricode += '%s %s\n'%(ins.mnemonic, ins.op_str)

        patchmap[patch_token] = (patch_off, patch_addr, patch_len)

    binm.close()
    binf.close()

    oriasm = tempfile.NamedTemporaryFile()
    oriasm.write(oricode.encode('utf-8'))
    oriasm.flush()
    orielf = tempfile.NamedTemporaryFile()
    compile_payload(oriasm.name, orielf.name)
    payobj = tempfile.NamedTemporaryFile()
    link_payload([payelf.name, orielf.name], 0x0, payobj.name, True)
    paytext = tempfile.NamedTemporaryFile()
    dump_binary(payobj.name, paytext.name)

    paytext_size = os.stat(paytext.name).st_size
    text_off = None
    text_addr = None
    for off, addr, size in poslist:
        # The linker will align the section.
        if (size - (addr & 0xF)) >= paytext_size:
            text_off = off
            text_addr = addr
            break

    funclist = link_payload([payelf.name, orielf.name],
            text_addr, payobj.name, True)
    dump_binary(payobj.name, paytext.name)

    patchpos = get_patchpos(funclist)
    patchcode = list()
    padins, _ = ks.asm('nop')
    for patch_token, target_addr in patchpos:
        patch_off, patch_addr, patch_len = patchmap[patch_token]
        jmpins, _ = ks.asm('jmp 0x%x'%target_addr, patch_addr)
        code = bytes(jmpins + padins * (patch_len - len(jmpins)))
        patchcode.append((patch_off, code))

    append(binpath, paytext.name, text_off, text_addr, outputpath)

    # Write the patch.
    with open(outputpath, 'r+b') as outputf:
        for patch_off, code in patchcode:
            outputf.seek(patch_off)
            outputf.write(code)


if __name__ == '__main__':
    main()
