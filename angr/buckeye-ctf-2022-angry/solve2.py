import angr
import sys

path_to_binary = "./angry"
project = angr.Project(path_to_binary)
initial_state = project.factory.blank_state(addr=0x4012e6)
simulation = project.factory.simgr(initial_state)

simulation.explore(find=0x4013c1, avoid=0x4013cf)

if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(1))
    print(solution_state.posix.dumps(0))
else:
    raise Exception('Could not find the solution')