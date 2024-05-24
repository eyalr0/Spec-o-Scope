import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm

counts_1 = []
counts_2 = []
counts_t = []
with open('paper_expr/sbox_sr_traces.txt', 'r') as f:
    for line in tqdm(f):
        if not line.startswith('key='):
            continue
        _, keyi, testi, cts = line.split('=')
        key_idx = int(keyi[:-2])
        test_idx = int(testi[:-12])
        sc1, sc2 = cts.split('[')[1][:-2].split(', ')
        c1 = int(sc1)
        c2 = int(sc2)
        ct = c1 + c2
        counts_1.append(c1)
        counts_2.append(c2)
        counts_t.append(ct)
        # print(key_idx, test_idx, c1, c2, ct)

sns.histplot({
    'Selecting witness': counts_1,
    'Measuring 1024 for witness': counts_2,
    'Total': counts_t
}, stat='probability')
plt.xlabel('Number of traces')
# plt.legend()
plt.savefig('paper_expr/sbox_sr_traces.png')
plt.close()