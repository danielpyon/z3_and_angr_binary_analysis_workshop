from z3 import *
import sys
from typing import List

def recover_seed(samples: List[int]) -> int:
	def update_seed():
		nonlocal seed
		seed = (seed*0x5DEECE66D+0xB)&((1<<48)-1)

	def next(bits=32):
		nonlocal seed
		update_seed()
		out = LShR(seed, 48-bits)&0xFFFFFFFF
		
		# if sign bit set, subtract stuff
		return If(out&0x80000000!=0, -0x100000000+out, out)

	def next_long():
		nonlocal seed
		return (next() << 32) + next()

	seed = BitVec('seed', 64)
	orig = seed
	seed = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)
	
	s = Solver()
	for i in range(len(samples)):
		s.add(next_long() == samples[i])

	assert s.check() == sat
	return s.model()[orig].as_long()

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('File of sample output required')
		sys.exit(1)
	
	samples_path = sys.argv[1]
	with open(samples_path, 'r') as f:
		samples = f.read().split('\n')[:-1]

	print('Loaded {} sample outputs'.format(len(samples)))
	samples = [int(x) for x in samples]

	original_seed = recover_seed(samples)
	print(hex(original_seed))
