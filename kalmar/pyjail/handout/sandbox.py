import ast
inp = input('Give me max 72 chars!\n> ')[:72]
if '__' in inp or not inp.isascii() or any(c.isspace() for c in inp):
    quit('Blocked!')
code = ast.dump(ast.parse(inp, mode='eval')).lower()
if any(banned in code for banned in ['iter', 'gen', 'comprehension']):
    quit('Iterating is bad')
eval(inp, {'__builtins__':{}})