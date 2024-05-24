import numpy as np
from tqdm import tqdm
import itertools
from AES.softAES import AES
import sys
import matplotlib.pyplot as plt
import seaborn as sns

MAX_CTS = 5000
CT_STEP = 10

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

# Assume line 16 is monitored (0th line in T1)
def get_acc_round(key, ct):
	aes = AES(key)
	_, table_nibbles = aes.decrypt_debug(ct)
	t1_nibbles = table_nibbles[1]
	assert(len(t1_nibbles) == 4*9)
	for i in range(9):
		if 0 in t1_nibbles[4*i:][:4]:
			return i
	return 9

# Assume line 16 is monitored (0th line in T1)
def get_acc_round_opt(cipher, ct):
	_, table_nibbles = cipher.decrypt_debug(ct)
	t1_nibbles = table_nibbles[1]
	assert(len(t1_nibbles) == 4*9)
	for i in range(9):
		if 0 in t1_nibbles[4*i:][:4]:
			return i
	return 9

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

				# if a1 % 10 == 0: continue
				# if a2 % 10 == 0: continue

				# a1 = fs_ps_correct(a1)
				# a2 = fs_ps_correct(a2)
				data.append((ct, a2 - a1))
			samples.append((key, data))
	assert(len(samples) == KEY_COUNT)

	# samples = samples[:20]

	round0 = []
	round1 = []
	later = []
	for key, data in tqdm(samples):
		cipher = AES(key)
		for ct, t in data:
			r = get_acc_round_opt(cipher, ct)
			if r == 0:
				round0.append(t)
			elif r == 1:
				round1.append(t)
			else:
				later.append(t)
	
	sns.kdeplot(round0, label='First Round')
	sns.kdeplot(round1, label='Second Round')
	sns.kdeplot(later, label='Later Rounds')
	plt.xlim((-20, 60))
	plt.legend()
	plt.xlabel('Attacker difference')
	plt.savefig('paper_expr/ttable_msb_oracle.png')
	plt.close()
			

