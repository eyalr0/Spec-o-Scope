from collections import OrderedDict
import matplotlib.pyplot as plt
import argparse
import numpy
import re


XLABEL = "Time in rdtsc cycles"
YLABEL = "amount"

TITLE = "Graph of 'test_fetch' %s"


def main(args):
    bins = numpy.arange(0, 200, 1)
    with args.input as f:
        results = OrderedDict(ram=[], llc=[], l2=[], l1=[])
        for line in f.readlines():
            for key in results.keys():
                re_res = re.findall(f"([\d]+) .*{key.upper()}", line)
                if len(re_res) == 1:
                    results[key].append(int(re_res[0]))

        for key in results.keys():
            mean = numpy.mean(results[key])
            AVERAGE_OVERHEAD = 44.11
            print(f'{key.upper()}: Mean: {mean:.1f} Adjusted Mean: {mean - AVERAGE_OVERHEAD:.1f}')
            plt.hist(results[key], bins, alpha=0.7, label=key)

        plt.title(TITLE % args.extra_title_text)
        plt.xlabel(XLABEL)
        plt.ylabel(YLABEL)
        plt.legend(loc="upper right")
        plt.savefig('fetch_graph.png')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--input", type=argparse.FileType("r"), required=True)
    parser.add_argument("-e", "--extra-title-text", default="")
    main(parser.parse_args())
