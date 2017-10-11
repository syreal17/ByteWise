import sys
import os


if __name__ == "__main__":
    data_folder = sys.argv[1]
    label_folder = sys.argv[2]

    fn_set = set()
    fn_order = list()

    for filename in os.listdir(data_folder):
        fn_set.add(filename)

    # DATA
    for fn_to_change in os.listdir(data_folder):
        num_new = fn_set.pop()
        fn_order.append(num_new)
        fn_new = fn_to_change[:-4] + "_" + num_new
        os.rename(data_folder + fn_to_change, data_folder + fn_new)

    for fn_new in os.listdir(data_folder):
        fn_done = fn_new.split("_")[1]
        os.rename(data_folder + fn_new, data_folder + fn_done)

    # LABELS
    for fn_to_change in os.listdir(label_folder):
        num_new = fn_order.pop(0)
        fn_new = fn_to_change[:-4] + "_" + num_new
        os.rename(label_folder + fn_to_change, label_folder + fn_new)

    for fn_new in os.listdir(label_folder):
        fn_done = fn_new.split("_")[1]
        os.rename(label_folder + fn_new, label_folder + fn_done)