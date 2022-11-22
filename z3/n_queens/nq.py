import sys
from z3 import *

def Abs(val:Int)->Int:
    return If(val < 0, -val, val)

if __name__ == '__main__':
    assert len(sys.argv) > 1
    n = int(sys.argv[1])

    columns = [Int(f'col_{i}') for i in range(n)]
    rows = [Int(f'row_{i}') for i in range(n)]

    s = Solver()
    
    for i in range(n):
        s.add(columns[i] >= 0, columns[i] < n, rows[i] >= 0, rows[i] < n)

    s.add(Distinct(rows))
    s.add(Distinct(columns))

    for i in range(n-1):
        for j in range(i+1,n):
            s.add(Abs(columns[i] - columns[j]) != Abs(rows[i] - rows[j]))

    if s.check() == sat:
        m = s.model()
        print(m)

