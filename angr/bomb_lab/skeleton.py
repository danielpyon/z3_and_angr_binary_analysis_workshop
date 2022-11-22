import angr

KABOOM_OFFSET = 0x133b

def phase_one(p, base):
	state = p.factory.blank_state(addr=base+0xf73)
	sm = p.factory.simulation_manager(state)

	sm.explore(find=base+0xf5d, avoid=base+KABOOM_OFFSET)
	found = sm.found[0]

	# rdi still holds string
	mem = found.memory.load(found.regs.rdi, 256)
	answer = found.solver.eval(mem, cast_to=bytes)
	out = answer[:answer.index(b'\x00')]

	print(out)

def phase_two(p, base):
	state = p.factory.blank_state(addr=base+0xb22)

	# set up arguments to phase_two
	arg_one = state.solver.BVS('arg_one', 8*128)
	arg_one_addr = 0x41414141
	state.memory.store(arg_one_addr, arg_one)
	state.add_constraints(state.regs.rdi == arg_one_addr)

	arg_two = state.solver.BVS('arg_two', 8*128)
	arg_two_addr = 0x42424242
	state.memory.store(arg_two_addr, arg_two)
	state.add_constraints(state.regs.rsi == arg_two_addr)

	arg_three = state.solver.BVS('arg_three', 8*128)
	arg_three_addr = 0x43434343
	state.memory.store(arg_three_addr, arg_three)
	state.add_constraints(state.regs.rdx == arg_three_addr)

	sm = p.factory.simulation_manager(state)
	sm.explore(find=base+0xf5d, avoid=base+KABOOM_OFFSET)
	found = sm.found[0]

	ret = []
	for arg in [arg_one, arg_two, arg_three]:
		answer = found.solver.eval(arg, cast_to=bytes)
		ret.append(answer[:answer.index(b'\x00')])
	
	print(ret)

def phase_three(p, base):
	pass

def phase_four(p, base):
	"""
	If you have a big array of memory you want splitting into individual integers, this might help: 
	#Convert to little endian and flip args as they'll have read out backwards
	args = []
	for i in range(20):
		val = (answer >> 8 * 4 * i) & 0xFFFFFFFF
		out = struct.unpack('<I', struct.pack('>I', val))[0]
		args.append(str(out))
	args.reverse()
	print(' '.join(args))
	"""
	pass	

def phase_five(p, base):
	pass

def phase_six(p, base):
	pass

if __name__ == "__main__":
	p = angr.Project('bomb',load_options={"auto_load_libs":False})
	base = p.loader.main_object.min_addr
	print("Phase one:")
	phase_one(p, base)
	print("Phase two:")
	phase_two(p, base)
	print("Phase three:")
	phase_three(p, base)
	print("Phase four:")
	phase_four(p, base)
	print("Phase five:")
	phase_five(p, base)
	print("Phase six:")
	phase_six(p, base)
