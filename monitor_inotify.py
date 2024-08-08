import argparse
from inotify_simple import INotify, flags

def parse_arguments():
    parser = argparse.ArgumentParser(description="Monitor directory access using inotify.")
    parser.add_argument("path", help="The directory path to monitor.")
    parser.add_argument("--allow", nargs='*', help="List of allowed directories.", default=[])
    parser.add_argument("--deny", nargs='*', help="List of denied directories.", default=[])
    return parser.parse_args()

def main():
    args = parse_arguments()
    inotify = INotify()
    watch_flags = flags.OPEN | flags.ACCESS | flags.CLOSE_WRITE | flags.CLOSE_NOWRITE
    wd = inotify.add_watch(args.path, watch_flags)

    print(f"Monitoring path: {args.path}")

    try:
        while True:
            for event in inotify.read():
                for flag in flags.from_mask(event.mask):
                    filepath = f"{args.path}/{event.name}" if event.name else args.path
                    if any(filepath.startswith(allowed) for allowed in args.allow):
                        print(f"Access allowed: {filepath} (event: {flag})")
                    elif any(filepath.startswith(denied) for denied in args.deny):
                        print(f"Access denied to {filepath} (event: {flag}) - Error!")
                    else:
                        print(f"Access to monitored path detected: {filepath} (event: {flag})")
    except KeyboardInterrupt:
        print("Monitoring stopped.")
    finally:
        inotify.rm_watch(wd)

if __name__ == "__main__":
    main()
