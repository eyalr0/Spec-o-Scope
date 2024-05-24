import numpy as np
from tqdm import tqdm
import itertools
from AES.softAES import AES
import matplotlib.pyplot as plt
import seaborn as sns
import random

KEY_COUNT = 1000
TEST_COUNT = 5

WITNESS_THRESHOLD = 70

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

def is_witness(key, ct, line=0):
	rk = get_round_key_bytes(AES(key)._Kd[0])
	for i in range(16):
		if (ct[i] >> 6) ^ line == rk[i] >> 6:
			return False
	return True
  
def is_sr_witness(key, ct, line=0):
	if not is_witness(key, ct, line=line):
		return False
	
	cs = AES(key)
	_, states, _ = cs.decrypt_debug2(ct)
	st = get_round_key_bytes(states[1])
	for i in range(16):
		if st[i] >> 6 == line:
			return False
	return True

def is_witness_opt(cipher, ct, line=0):
	rk = get_round_key_bytes(cipher._Kd[0])
	for i in range(16):
		if (ct[i] >> 6) ^ line == rk[i] >> 6:
			return False
	return True
  
def is_sr_witness_opt(cipher, ct, line=0):
	if not is_witness_opt(cipher, ct, line=line):
		return False
	
	_, states, _ = cipher.decrypt_debug2(ct)
	st = get_round_key_bytes(states[1])
	for i in range(16):
		if st[i] >> 6 == line:
			return False
	return True

def fast_pearson(x, y):
	x = np.array(x)
	y = np.array(y)
	xv = x - x.mean(axis=0)
	yv = y - y.mean(axis=0)
	xvss = (xv * xv).sum(axis=0)
	yvss = (yv * yv).sum(axis=0)
	result = np.matmul(xv.transpose(), yv) / np.sqrt(np.outer(xvss, yvss))
	return np.maximum(np.minimum(result, 1.0), -1.0)[0][0]

def true_sample(x):
	y = x % 10 + (x // 10) * 20
	if x % 10 == 0:
		y -= 5
	return y

if __name__ == '__main__':
	filename = "paper_expr/sbox_sr.txt"
	REPEAT = 1

	samples = []
	with open(filename, 'r') as f:
		for chunk in tqdm(chunks(f.readlines(), TEST_COUNT * 1024 * REPEAT)):
			assert(len(chunk) == TEST_COUNT * 1024 * REPEAT)
			key = None
			key_data = []
			for chunk2 in chunks(chunk, 1024 * REPEAT):
				data = []
				for line in chunk2:
					parts = line[:-1].split(',')
					cur_key = bytes.fromhex(parts[0])
					if key is None:
						key = cur_key
					else:
						assert(key == cur_key)
					ct = bytes.fromhex(parts[1])
					a1, a2 = int(parts[2]), int(parts[3])

					if a1 == -1:
						# continue # TODO: ???
						a1 = 0
						a2 = 0
					if a2 == -1:
						# a2 = a1 + 50 # NOTE: Treat no access as late access
						a1 = 0
						a2 = 0

					if False and (a1 % 10 == 0 or a2 % 10 == 0):
						# Discard traces which landed in the overhead window
						continue
						# a1 = 0
						# a2 = 0

					a1 = true_sample(a1)
					a2 = true_sample(a2)
					data.append((ct, a2 - a1))
				
				# print(f'discarded {TEST_COUNT - len(data)}')
				key_data.append(data)
			samples.append((key, key_data))
	assert(len(samples) == KEY_COUNT)

	random.seed(0x307cca9dca80e9eb)
	round1 = []
	later = []
	for key, key_data in tqdm(random.sample(samples, 100)):
		cipher = AES(key)
		for data in key_data:
			for ct, t in data[1:]: # Skip first one for without majority
				if not is_sr_witness_opt(cipher, ct):
					round1.append(t)
				else:
					later.append(t)

	sns.kdeplot(round1, label='Second Round')
	sns.kdeplot(later, label='Later Rounds')
	plt.legend()
	plt.xlabel('Attacker difference [Adjusted]')
	# plt.xlim(left=-50)
	plt.savefig('paper_expr/sbox_sr_oracle.png')
	plt.close()