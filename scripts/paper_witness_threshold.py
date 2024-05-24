import matplotlib.pyplot as plt
import seaborn as sns
from AES.softAES import AES

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
        for chunk in chunks(f.readlines(), TEST_COUNT):
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

samples = load_file(f"paper_expr/sbox_msb.txt", first=10)

key, data = samples[5]

f, axs = plt.subplots(1, 4, figsize=(16,5), sharey=True)

WITNESS_THRESH = 20

for nibble in range(4):
  ax = axs[nibble]

  wb_count = 0

  gaps = []
  gaps_x = []
  wg = []
  wg_x = []
  iwg = []
  iwg_x = []
  fp = []
  fp_x = []
  x = 0
  for ct, a1, a2 in data:
    if ct[0] >> 6 != nibble:
      continue
    g = a2 - a1

    # if WITNESS_BAND[0] <= g <= WITNESS_BAND[1]:
    #   wb_count += 1

    if is_witness(key, ct):
      wg.append(g)
      wg_x.append(x)
    elif is_witness(key, ct, line=3):
      iwg.append(g)
      iwg_x.append(x)
    elif abs(g) >= WITNESS_THRESH:
      fp.append(g)
      fp_x.append(x)
    else:
      gaps.append(g)
      gaps_x.append(x)
    x += 1
  ax.set_xlabel(hex(nibble))
  ax.set_xlim((0, len(data)//4))

  y_bt, y_tp = -77, 67
  ax.axhspan(WITNESS_THRESH, y_tp, color='lightblue', alpha=0.4)
  ax.axhspan(y_bt, -WITNESS_THRESH, color='lightblue', alpha=0.4)
  ax.set_ylim((y_bt, y_tp))

  sns.scatterplot(x=gaps_x, y=gaps, linewidth=0, color='lightgray', s=10, alpha=.9,
                    label='Non-Witness', ax=ax)

  sns.scatterplot(x=wg_x, y=wg, linewidth=0, color='green', marker='D', s=10,
                    label='Line 0 Witness', ax=ax)
  sns.scatterplot(x=iwg_x, y=iwg, linewidth=0, color='purple', marker='D', s=10,
                    label='Line 3 Witness', ax=ax)
  sns.scatterplot(x=fp_x, y=fp, linewidth=0, color='red', marker='v', s=10,
                    label='False Positive', ax=ax)

  ax.tick_params(axis='x', which='both', bottom=False, top=False, labelbottom=False)
  ax.set_ylabel('Difference Between Attackers')

lines, labels = [], []
for ax in axs:
  aln, alb = ax.get_legend_handles_labels()
  for ln, lb in zip(aln, alb):
    if lb not in labels:
      lines.append(ln)
      labels.append(lb)
  if ax.get_legend() is not None:
    ax.get_legend().remove()
plt.legend(lines, labels, loc='upper right', framealpha=1)

f.tight_layout(pad=1.5)
f.subplots_adjust(wspace=0)
f.suptitle('Corresponding Ciphertext Byte Value', y=0.04)
plt.savefig('paper_expr/sbox_msb_threshold.png')