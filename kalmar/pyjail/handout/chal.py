import ast
inp = input('Give me max 72 chars!\n> ')[:72]

# This by itself should be enough to make it safe: https://news.ycombinator.com/item?id=47502448
if '__' in inp:
    quit('No dunders!')

# But let's add some more protections
if not inp.isascii():
    quit('Only ascii please')

# You only need whitespace in exec context
if any(c.isspace() for c in inp):
    quit('No whitespace!')

# No funny business with iterables
code = ast.dump(ast.parse(inp, mode='eval')).lower()
# Too lazy to traverse tree, so let's just do a string check
if any(banned in code for banned in ['iter', 'gen', 'comprehension']):
    quit('Iterating is bad, you must do it first try')

# Now it's finally safe
eval(inp, {'__builtins__':{}})