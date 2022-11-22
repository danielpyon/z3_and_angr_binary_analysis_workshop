from z3 import *
import sys
import random

def solve(puzzle):
    # Puzzle is an 81 character string representing a suduko board
    # '.' characters are used for unknown squares and numbers for known
    # values, return a string representing a completed suduko board	

    s = Solver()

    board = [[Int(f'row_{i} col_{j}') for j in range(9)] for i in range(9)]
    
    # get num in puzzle, -1 if doesn't exist
    def get_num(i, j):
        sym = puzzle[9*i+j]
        if sym == '.':
            return -1
        return int(sym)

    # add known constraints to solver
    for i in range(9):
        for j in range(9):
            s.add(And(board[i][j] >= 1, board[i][j] <= 9))

            constraint = get_num(i, j)
            if constraint == -1:
                continue
            s.add(board[i][j] == constraint)

    # rows unique
    for i in range(9):
        # all vals in board[i] must be distinct
        s.add(Distinct([board[i][j] for j in range(9)]))
    
    # cols unique
    for i in range(9):
        s.add(Distinct([board[j][i] for j in range(9)]))
    
    # each square must use 1-9 once
    for x in range(0, 9, 3):
        for y in range(0, 9, 3):
            # square
            square_constraint = []
            for i in range(3):
                for j in range(3):
                    square_constraint.append(board[i][j])
            s.add(Distinct(square_constraint))

    if not s.check():
        raise Exception('unsatisfiable!')

    m = s.model()
    solved = ''
    for i in range(9):
        for j in range(9):
            assignment = m[board[i][j]]
            solved += str(assignment)
    return solved

# Print a rather vague Suduko board
def draw_puzzle(puzzle):
    for i in range(9):
        out = "|"
        for j in range(9):
            out += str(puzzle[(9*i)+j]) + "|"
        print(out)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("path to testcase file expected")
        sys.exit(1)
    
    test_path = sys.argv[1]

    with open(test_path, 'r') as f:
        samples = f.read().split('\n')[:-1]
    
    print("Selecting random puzzle out of {} samples".format(len(samples)))
    puzzle = random.choice(samples)
    draw_puzzle(puzzle)

    print("")
    print("-" * 30)
    print("")
    
    # Solve the puzzle?
    solution = solve(puzzle)
    # Draw solved grid
    draw_puzzle(solution)
