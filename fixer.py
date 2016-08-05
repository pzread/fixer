#!/usr/bin/python3
import argparse
import mmap
import os
import re
import struct
import subprocess
import sys
import tempfile
from capstone import *


SCRIPT_DIR = os.path.dirname(sys.argv[0]) + '/'
SRC_DIR = os.path.join(SCRIPT_DIR, 'src') + '/'
SCAN_TOOL = os.path.join(SCRIPT_DIR, 'bin/scan')
APPEND_TOOL = os.path.join(SCRIPT_DIR, 'bin/append')
LINKER_SCRIPT = os.path.join(SRC_DIR, 'payload.lds')


def scan(binpath):
    data = subprocess.check_output([SCAN_TOOL, binpath])
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
            poslist.append((off + fsize, addr + msize, 0x1000 - rel))

    tail_off = (os.stat(binpath).st_size + 0xFFF) & ~0xFFF
    tail_addr = (tail_addr + 0xFFF) & ~0xFFF
    poslist.append((tail_off, tail_addr, 256 ** 4))

    return entry, phlist, poslist


def vaddr_offset(phlist, vaddr):
    for off, addr, fsize, _ in phlist:
        if vaddr >= addr and vaddr < (addr + fsize):
            return off + (vaddr - addr)

    return None


def compile_payload(paypath, outpath, asm):
    if asm == 'nasm':
        subprocess.check_output(['nasm', '-O0', '-f', 'elf', '-I', SRC_DIR,
                '-o', outpath, paypath])
    elif asm == 'as':
        subprocess.check_output(['as', '--32', '-o', outpath, paypath])


def link_payload(elfpaths, text_addr, outpath, static=False):
    params = ['ld', '-m', 'elf_i386', '-T', LINKER_SCRIPT,
            '--oformat', 'elf32-i386', '-Ttext={:#x}'.format(text_addr),
            '-o', outpath]
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
    subprocess.check_output([APPEND_TOOL, binpath, outpath,
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

    entry_addr, phlist, poslist = scan(binpath)

    print('Offset Address Size')
    for (off, addr, size) in poslist:
        print('{:#08x} {:#08x} {}'.format(off, addr, size))

    if paypath is None:
        return

    payelf = tempfile.NamedTemporaryFile()
    compile_payload(paypath, payelf.name, 'nasm')
    with tempfile.NamedTemporaryFile() as tmpobj:
        funclist = link_payload([payelf.name], 0x0, tmpobj.name)

    # Generate the helper code.
    patchpos = get_patchpos(funclist)
    patchmap = dict()
    oricode = ['.intel_syntax noprefix', '.section .backtext']
    with open(binpath, 'r+b') as binf:
        binm = mmap.mmap(binf.fileno(), 0)
        for patch_token, _ in patchpos:
            if patch_token == 'ENTRY':
                patch_addr = entry_addr
            else:
                patch_addr = int(patch_token, 16)
            patch_off = vaddr_offset(phlist, patch_addr)
            patch_len = 0

            for idx, ins in enumerate(cs.disasm(binm[patch_off:], patch_addr)):
                if idx < 2:
                    if idx == 0:
                        token = 'back_{}'.format(patch_token)
                    elif idx == 1:
                        token = 'skip_{}'.format(patch_token)
                    oricode.append('.global {}'.format(token))
                    oricode.append('{}:'.format(token))

                if ins.address - patch_addr >= 5:
                    patch_len = ins.address - patch_addr
                    oricode.append('jmp {:#x}'.format(ins.address))
                    break

                oricode.append('{} {}'.format(ins.mnemonic, ins.op_str))

            patchmap[patch_token] = (patch_off, patch_addr, patch_len)

        binm.close()

    #oriasm = tempfile.NamedTemporaryFile()
    oriasm = open('x', 'wb')
    oriasm.write(('\n'.join(oricode) + '\n').encode('utf-8'))
    oriasm.flush()
    orielf = tempfile.NamedTemporaryFile()
    compile_payload(oriasm.name, orielf.name, 'as')
    payobj = tempfile.NamedTemporaryFile()
    link_payload([payelf.name, orielf.name], 0x0, payobj.name, True)
    paytext = tempfile.NamedTemporaryFile()
    dump_binary(payobj.name, paytext.name)

    # Find the suitable position.
    paytext_size = os.stat(paytext.name).st_size
    text_off = None
    text_addr = None
    for off, addr, size in poslist:
        # The linker will align the section.
        if (size - (addr & 0xF)) >= paytext_size:
            text_off = off
            text_addr = addr
            break

    print('Append at {:#08x}'.format(text_addr))

    funclist = link_payload([payelf.name, orielf.name],
            text_addr, payobj.name, True)
    dump_binary(payobj.name, paytext.name)

    # Generate patch code.
    patchpos = get_patchpos(funclist)
    patchcode = list()
    for patch_token, target_addr in patchpos:
        patch_off, patch_addr, patch_len = patchmap[patch_token]
        jmpdis = (target_addr - patch_addr - 5) & 0xFFFFFFFF
        jmpins = b'\xE9' + struct.pack('I', jmpdis)
        code = bytes(jmpins + b'\x90' * (patch_len - len(jmpins)))
        patchcode.append((patch_off, code))

    append(binpath, paytext.name, text_off, text_addr, outputpath)

    # Write the patch.
    with open(outputpath, 'r+b') as outputf:
        for patch_off, code in patchcode:
            outputf.seek(patch_off)
            outputf.write(code)


if __name__ == '__main__':
    main()
