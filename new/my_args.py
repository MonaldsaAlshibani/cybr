import argparse 

def sum_num(numbers):
    return sum(numbers)


def main(): 
    parser = argparse.ArgumentParser(description="Tiny Demo")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_greet = sub.add_parser("greet", help="Say hello")
    p_greet.add_argument("--name", required=True)

    p_add = sub.add_parser("sum", help="sum all numbers")
    p_add.add_argument("numbers", nargs="+", type=int, help="integers to sum")
    parser.print_help()
    args = parser.parse_args()

    if args.cmd == "greet":
        print(f"Hello, {args.name}!")
    elif args.cmd == "sum":
        result = sum_num(args.numbers)
        print(f"Sum: {result}")

if __name__ == "__main__": 
    main()