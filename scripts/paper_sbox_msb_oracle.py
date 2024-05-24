import matplotlib.pyplot as plt
import seaborn as sns
from AES.softAES import AES
from tqdm import tqdm

def get_round_key_bytes(rk):
    byte_list = []
    for i in range(4):
        word = rk[i]
        byte_list.append((word >> 24) & 0xff)
        byte_list.append((word >> 16) & 0xff)
        byte_list.append((word >> 8) & 0xff)
        byte_list.append((word >> 0) & 0xff)
    return byte_list

def is_witness(key, ct, line=0):
    rk = get_round_key_bytes(AES(key)._Kd[0])
    for i in range(16):
        if (ct[i] >> 6) ^ line == rk[i] >> 6:
            return False
    return True

def is_witness_opt(rk, ct, line=0):
    for i in range(16):
        if (ct[i] >> 6) ^ line == rk[i] >> 6:
            return False
    return True

import itertools
def chunks(iterable, n):
    it = iter(iterable)
    while batch := tuple(itertools.islice(it, n)):
        yield batch

TEST_COUNT = 10_000
KEY_COUNT = 1_000

def true_sample(x):
  y = x % 10 + (x // 10) * 20
  if x % 10 == 0:
    y -= 5
  return y

def load_file(filename, discard=False, first=None):
    samples = []
    with open(filename, 'r') as f:
        for chunk in tqdm(chunks(f.readlines(), TEST_COUNT)):
            assert(len(chunk) == TEST_COUNT)
            key = None
            data = []
            for line in chunk:
                parts = line[:-1].split(',')
                cur_key = bytes.fromhex(parts[0])
                if key is None:
                    key = cur_key
                else:
                    assert(key == cur_key)
                ct = bytes.fromhex(parts[1])
                a1, a2 = int(parts[2]), int(parts[3])

                if a1 == -1 or a2 == -1:
                  data.append((ct, -1, -1))
                else:
                  data.append((ct, a1, a2))

            if discard:
                # Discard traces which landed in the overhead window
                data = [x for x in data if (x[1] % 10 != 0) and (x[2] % 10 != 0)]

            samples.append((key, data))
            if first is not None and len(samples) == first:
               break


    return samples

samples = load_file(f"paper_expr/sbox_msb.txt")

round0 = []
later = []
later_neg = []
for key, data in tqdm(samples):
    cipher = AES(key)
    rk = get_round_key_bytes(cipher._Kd[0])
    for ct, a1, a2 in data:
        t = a2 - a1
        if is_witness_opt(rk, ct):
            later.append(t)
        elif is_witness_opt(rk, ct, line=3):
            later_neg.append(t)
        else:
            round0.append(t)

sns.kdeplot(round0, label='Non-Witness')
sns.kdeplot(later, label='Cache Line 0 Witness')
sns.kdeplot(later_neg, label='Cache Line 3 Witness')
plt.legend()
plt.xlabel('Attacker difference')
# plt.xlim(left=-50)
plt.savefig('paper_expr/sbox_msb_oracle.png')
plt.close()