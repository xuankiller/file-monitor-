import subprocess
import argparse
import re

def parse_arguments():
    parser = argparse.ArgumentParser(description="Track system calls and detect directory access.")
    parser.add_argument("path", help="The directory path to monitor.")
    parser.add_argument("command", help="The shell command to execute.")
    parser.add_argument("--allow", nargs='*', help="List of allowed directories.", default=[])
    parser.add_argument("--deny", nargs='*', help="List of denied directories.", default=[])
    return parser.parse_args()

def run_strace(command):
    try:
        result = subprocess.run(['strace', '-e', 'trace=file', command], stderr=subprocess.PIPE, text=True, shell=True)
        return result.stderr
    except Exception as e:
        print(f"Error running strace: {e}")
        return None

def analyze_trace(trace_output, monitored_path, allowed_dirs, denied_dirs):
    accesses = re.findall(r'openat\(\d+, "([^"]+)",', trace_output)
    for access in accesses:
        if access.startswith(monitored_path):
            if any(access.startswith(allowed) for allowed in allowed_dirs):
                print(f"Access allowed: {access}")
            elif any(access.startswith(denied) for denied in denied_dirs):
                print(f"Access denied to {access} - Error!")
            else:
                print(f"Access to monitored path detected: {access}")

def main():
    args = parse_arguments()
    trace_output = run_strace(args.command)

    if trace_output:
        analyze_trace(trace_output, args.path, args.allow, args.deny)

if __name__ == "__main__":
    main()