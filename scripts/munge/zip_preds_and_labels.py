import sys

if __name__ == "__main__":
    label_dir = sys.argv[1]
    pred_dir = sys.argv[2]
    zip_fn = sys.argv[3]
    num_min = int(sys.argv[4])
    num_max = int(sys.argv[5])

    zip_f = open(zip_fn, "w")
    for d in range(num_min,num_max+1):
        label_f = open(label_dir + str(d) + ".csv", "r")
        pred_f = open(pred_dir + str(d), "r")

        for _ in range(0,1000):
            label_line = label_f.readline()
            label_line = label_line[:-1]
            pred_line = pred_f.readline()
            pred_line = pred_line[:-1]
            zip_line = pred_line + ", " + label_line + "\n"
            zip_f.write(zip_line)

        label_f.close()
        pred_f.close()

    zip_f.close()
