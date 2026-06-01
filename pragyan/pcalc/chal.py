#!/usr/bin/env python3
import ast
import sys
import os

def audit_hook(event, args):
    if event in ['os.system', 'os.popen', 'os.spawn', 'subprocess.Popen']:
        raise RuntimeError("Blocked Action Detected")
    
    if event == 'open' and isinstance(args[0], str) and 'flag' in args[0]:
        raise RuntimeError("Forbidden File Access")

sys.addaudithook(audit_hook)

class Calculator(ast.NodeVisitor):
    def __init__(self):
        self.is_valid = True

    def visit(self, node):
        if isinstance(node, (ast.Module, ast.Expr, ast.BinOp, ast.UnaryOp, 
                             ast.Constant, ast.Name, ast.Load, 
                             ast.operator, ast.unaryop)):
            super().visit(node)
        elif isinstance(node, ast.JoinedStr):
            pass
        else:
            print(f"Forbidden node type '{type(node).__name__}'")
            self.is_valid = False

def run_jail():
    print("Welcome to pCalc")
    print("+, -, *, and / are supported")
    
    user_input = input(">>> ")

    if "import" in user_input:
        print("'import' is a bad word.")
        return

    try:
        tree = ast.parse(user_input)
    except SyntaxError:
        print("Invalid Syntax")
        return

    validator = Calculator()
    validator.visit(tree)

    if not validator.is_valid:
        print("Expression rejected")
        return

    safe_globals = {"__builtins__": {}} 
    try:
        result = eval(user_input, safe_globals)
        if isinstance(result, (int, float, complex)):
            print(result)
        else:
            print("Error: Calculator only supports numbers.")
    except Exception as e:
        print(f"Runtime Error: {e}")

run_jail()

