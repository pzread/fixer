#!/usr/bin/python3
import mmap
import argparse
import subprocess
import sys
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
    for line in lines:
        line = line.rstrip('\n')
        if len(line) == 0:
            break
        off, addr, fsize = line.split(' ')
        off = int(off)
        addr = int(addr)
        fsize = int(fsize)
        phlist.append((off, addr, fsize))
    lines = lines[len(phlist) + 1:]

    poslist = list()
    print('Offset Address Size')
    for line in lines:
        if len(line) == 0:
            break
        off, addr, size = line.rstrip('\n').split(' ')
        off = int(off)
        addr = int(addr)
        size = int(size)
        poslist.append((off, addr, size))
        print('0x%08x 0x%08x 0x%016x'%(off, addr, size))

    return entry, phlist, poslist


def vaddr_offset(phlist, vaddr):
    for off, addr, size in phlist:
        if vaddr >= addr and vaddr < (addr + size):
            return off + (vaddr - addr)
    return None


def compile_payload(paypath, outpath):
    subprocess.check_output(['nasm', '-f', 'elf', '-o', outpath, paypath])


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
    print('Name Address')
    for line in data.split('\n'):
        parts = line.rstrip('\n').split(' ')
        if len(parts) < 3:
            continue
        if parts[1] != 'g':
            continue
        funcpair = (parts[-1], int(parts[0], 16))
        print('%s 0x%08x'%funcpair)
        funclist.append(funcpair)

    return funclist


def dump_binary(objpath, textpath):
    subprocess.check_output(['objcopy', '-O', 'binary', '-j', '.text',
            objpath, textpath])


def patch(binpath, textpath, text_off, text_addr, outpath):
    subprocess.check_output(['./bin/patch', binpath, outpath,
            textpath, str(text_off), str(text_addr)])


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

    entry, phlist, poslist = scan(binpath)
    if paypath is None:
        return

    text_off, text_addr, _ = poslist[0]

    payelf = tempfile.NamedTemporaryFile()
    compile_payload(paypath, payelf.name)
    payobj = tempfile.NamedTemporaryFile()
    funclist = link_payload([payelf.name], text_addr, payobj.name)

    patchlist = list()
    for name, addr in funclist:
        if not name.startswith('patch_'):
            continue
        patch_token = name[len('patch_'):]
        patchlist.append((patch_token, addr))

    binf = open(binpath, 'r+b')
    binm = mmap.mmap(binf.fileno(), 0)
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    oricode = '[BITS 32]\nsection .backtext\n'
    patchcode = list()
    padins, _ = ks.asm('nop')
    for patch_token, addr in patchlist:
        patch_addr = int(patch_token, 16)
        patch_off = vaddr_offset(phlist, patch_addr)

        jmpins, _ = ks.asm('jmp 0x%08x'%addr, patch_addr)
        code = bytearray(jmpins)

        oricode += 'global back_%s\nback_%s:\n'%(patch_token, patch_token)
        for ins in cs.disasm(binm[patch_off:], patch_addr):
            over = ins.address - patch_addr - len(jmpins)
            if over >= 0:
                code.extend(padins * over)
                oricode += 'jmp 0x%08x\n'%ins.address
                break

            oricode += '%s %s\n'%(ins.mnemonic, ins.op_str)

        patchcode.append((patch_off, bytes(code)))

    binm.close()
    binf.close()

    oriasm = tempfile.NamedTemporaryFile()
    oriasm.write(oricode.encode('utf-8'))
    oriasm.flush()
    orielf = tempfile.NamedTemporaryFile()
    compile_payload(oriasm.name, orielf.name)
    funclist = link_payload([payelf.name, orielf.name], text_addr, payobj.name)
    paytext = tempfile.NamedTemporaryFile()
    dump_binary(payobj.name, paytext.name)

    patch(binpath, paytext.name, text_off, text_addr, outputpath)

    with open(outputpath, 'r+b') as outputf:
        for patch_off, code in patchcode:
            outputf.seek(patch_off)
            outputf.write(code)


if __name__ == '__main__':
    main()
