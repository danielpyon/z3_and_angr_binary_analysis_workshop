import angr

TARGET_OFFSET = 0x1013c1-0x100000
SCRAMBLE_OFFSET = 0x10137e-0x100000
AVOID_OFFSET = 0x1013cf-0x100000

def solve(p, base):
    state = p.factory.blank_state(addr=base+SCRAMBLE_OFFSET)

    answer = state.solver.BVS('answer', 8*34)
    answer_addr = 0x1337
    state.memory.store(answer_addr, answer)
    state.add_constraints(state.regs.rdi == answer_addr)

    state.regs.rsi = 42

    sm = p.factory.simulation_manager(state)
    sm.explore(find=base+TARGET_OFFSET, avoid=base+AVOID_OFFSET)
    found = sm.found[0]

    flag = found.solver.eval(answer, cast_to=bytes)
    print(flag)

if __name__ == '__main__':
    p = angr.Project('angry', load_options={'auto_load_libs': False})
    base = p.loader.main_object.min_addr
    solve(p, base)
