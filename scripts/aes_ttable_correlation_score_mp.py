import numpy as np
from math import sqrt
from tqdm import tqdm
import itertools
from AES.softAES import AES
from multiprocessing import Pool
import sys

MAX_CTS = 5000
CT_STEP = 10
MULT_BY_FOUR = False

TEST_COUNT = 4_000
KEY_COUNT = 1_000

def chunks(iterable, n):
    it = iter(iterable)
    while batch := tuple(itertools.islice(it, n)):
        yield batch

def get_round_key_bytes(rk):
    byte_list = []
    for i in range(4):
        word = rk[i]
        byte_list.append((word >> 24) & 0xff)
        byte_list.append((word >> 16) & 0xff)
        byte_list.append((word >> 8) & 0xff)
        byte_list.append((word >> 0) & 0xff)
    return byte_list

def worker(arg):
    key, sample, bc = arg
    gaps = np.array([s[1] for s in sample])
    cts = [s[0] for s in sample]

    round_key = AES(key)._Kd[0]

    sample_count = min(MAX_CTS, len(gaps))

    num_needed = 0
    for idx in [1, 5, 9, 13]:
        correct_nibble = get_round_key_bytes(round_key)[idx] >> 4
        scores = [[] for _ in range(16)]
        access_vecs = [np.array([0 if (ct[idx] >> 4) == nibble else 1 for ct in cts]) for nibble in range(16)]
        for n in range(CT_STEP, sample_count+CT_STEP, CT_STEP):
            gaps_n = gaps[:n]
            gaps_off_mean = gaps_n - gaps_n.mean()
            gaps_std = sqrt(np.sum(gaps_off_mean ** 2))
            for nibble in range(16):
                access_vec = access_vecs[nibble][:n]
                av_off_mean = access_vec - access_vec.mean()
                av_std = sqrt(np.sum(av_off_mean ** 2))

                if gaps_std == 0 or av_std == 0:
                    corr = 0
                else:
                    corr = np.sum(gaps_off_mean * av_off_mean) / (gaps_std * av_std)
                for _ in range(CT_STEP):
                    scores[nibble].append(corr)
        
        scores = np.array(scores)
        needed = 1
        for i in range(sample_count-2, -1, -1):
            if scores[correct_nibble, i] < np.max(scores[:, i]):
                needed = i + 1
                break
        num_needed = max(num_needed, needed)
    
    return num_needed + np.sum(np.array(bc) < num_needed)

def fs_ps_correct(x):
    SAMPLES_PER_WINDOW = 10
    WINDOW_LENGTH = 10
    if x > 0 and x % SAMPLES_PER_WINDOW == 0:
        windows = (x - 1) // SAMPLES_PER_WINDOW
        return x + windows * WINDOW_LENGTH + (WINDOW_LENGTH // 2)
    else:
        windows = x // SAMPLES_PER_WINDOW
        return x + windows * WINDOW_LENGTH

if __name__ == '__main__':
    filename = 'paper_expr/ttable_msb.txt'

    if len(sys.argv) > 1:
        filename = sys.argv[1]
    print(filename)

    samples = []
    with open(filename, 'r') as f:
        for chunk in tqdm(chunks(f.readlines(), TEST_COUNT)):
            assert(len(chunk) == TEST_COUNT)
            key = None
            data = []
            bc = []
            for line in chunk:
                parts = line[:-1].split(',')
                cur_key = bytes.fromhex(parts[0])
                if key is None:
                    key = cur_key
                else:
                    assert(key == cur_key)
                ct = bytes.fromhex(parts[1])
                a1, a2 = int(parts[2]), int(parts[3])

                if a1 == -1:
                    a1 = 0
                if a2 == -1:
                    a2 = a1 + 50 # NOTE: Treat no access as late access

                if a2 - a1 < 20:
                    bc.append(len(data))
                    continue
                # a1 = fs_ps_correct(a1)
                # a2 = fs_ps_correct(a2)
                data.append((ct, a2 - a1))
            samples.append((key, data, bc))
            if len(samples) == KEY_COUNT:
                break
    assert(len(samples) == KEY_COUNT)

    # samples = samples[:20]

    num_cts = []
    with Pool(processes=6) as p:
        num_cts = list(tqdm(p.imap(worker, samples), total=len(samples)))

    if MULT_BY_FOUR:
        num_cts = [x*4 for x in num_cts]

    with open('paper_expr/ttable_msb_traces.txt', 'w+') as f:
        for n in num_cts:
            f.write(str(n)+'\n')

    num_cts = np.array(num_cts)
    median = np.median(num_cts)
    percentile_10 = np.percentile(num_cts, 10)
    percentile_90 = np.percentile(num_cts, 90)
    print(f'{percentile_10:.1f} - {median:.1f} - {percentile_90:.1f}')

            

