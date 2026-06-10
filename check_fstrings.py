"""Check for unnecessary f-strings in Python files."""
import ast
import os

def check_file(filepath):
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        tree = ast.parse(content)
        lines = content.split('\n')
        
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                # Check if all values are constants (no expressions)
                if all(isinstance(v, ast.Constant) for v in node.values):
                    issues.append((node.lineno, lines[node.lineno - 1].strip()))
    except Exception as e:
        print(f"Error checking {filepath}: {e}")
    return issues

def main():
    backend_dir = r"D:\Vs Code\VS code\aether\backend\app"
    for root, dirs, files in os.walk(backend_dir):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                issues = check_file(filepath)
                if issues:
                    print(f"\n{filepath}:")
                    for line_no, line in issues:
                        print(f"  Line {line_no}: {line}")

if __name__ == "__main__":
    main()
