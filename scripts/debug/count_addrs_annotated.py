import sys
import pickle


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("First and only argument should be addr to annotation dictionary")

    f = open(sys.argv[1], "rb")
    addr_to_ann = pickle.load(f)

    i = 0
    for item in addr_to_ann:
        i += 1

    print i