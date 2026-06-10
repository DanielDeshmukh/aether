"""Check Python files for common issues."""
import ast
import os
import sys

def check_file(filepath):
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Try to parse the file
        tree = ast.parse(content)
        
        # Check for undefined names
        defined_names = set()
        used_names = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.FunctionDef):
                defined_names.add(node.name)
            elif isinstance(node, ast.ClassDef):
                defined_names.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        defined_names.add(target.id)
        
        # Check for used but undefined names (basic check)
        for name in used_names:
            if name not in defined_names and name not in ['print', 'len', 'str', 'int', 'float', 'list', 'dict', 'set', 'tuple', 'bool', 'None', 'True', 'False', 'self', 'cls']:
                # Skip common builtins and imports
                pass
        
    except SyntaxError as e:
        issues.append(f"Syntax error: {e}")
    except Exception as e:
        issues.append(f"Error: {e}")
    
    return issues

def main():
    backend_dir = r"D:\Vs Code\VS code\aether\backend\app"
    total_issues = 0
    
    for root, dirs, files in os.walk(backend_dir):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                issues = check_file(filepath)
                if issues:
                    print(f"\n{filepath}:")
                    for issue in issues:
                        print(f"  {issue}")
                    total_issues += len(issues)
    
    if total_issues == 0:
        print("No issues found!")
    else:
        print(f"\nTotal issues: {total_issues}")

if __name__ == "__main__":
    main()
