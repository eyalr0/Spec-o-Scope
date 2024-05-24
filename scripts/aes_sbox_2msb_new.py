import numpy as np
from math import sqrt
from tqdm import tqdm
import itertools
from AES.softAES import AES
from multiprocessing import Pool

TEST_COUNT = 10_000
KEY_COUNT = 1_000

WITNESS_THRESHOLD = 20

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
	(key, sample), byte_idx = arg
	gaps = np.array([s[1] for s in sample])
	cts = [s[0] for s in sample]

	round_key = AES(key)._Kd[0]

	sample_count = len(gaps) #min(MAX_CTS, len(gaps))

	correct_msbs = get_round_key_bytes(round_key)[byte_idx] >> 6

	num_needed = 0
	bc = [0]*4
	for i in range(sample_count):
		msbs = cts[i][byte_idx] >> 6
		if gaps[i] >= WITNESS_THRESHOLD:
			bc[msbs] += 1
		if gaps[i] <= -WITNESS_THRESHOLD:
			bc[msbs^3] += 1
		
		other_min = 10**10
		for j in range(4):
			if j != correct_msbs:
				other_min = min(other_min, bc[j])
		
		if bc[correct_msbs] >= other_min:
			num_needed = i + 1
	if num_needed == sample_count:
		num_needed = TEST_COUNT
	return num_needed

if __name__ == '__main__':
	filename = "paper_expr/sbox_msb.txt"

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
					a2 = 0
				if a2 == -1:
					a2 = a1 + 50 # NOTE: Treat no access as late access

				if False and (a1 % 10 == 0 or a2 % 10 == 0):
					# Discard traces which landed in the overhead window
					continue
					# a1 = 0
					# a2 = 0

				data.append((ct, a2 - a1))
			
			# print(f'discarded {TEST_COUNT - len(data)}')
			samples.append((key, data))
	assert(len(samples) == KEY_COUNT)


	cts_req = [0]*len(samples)
	for bi in range(16):
		print('====', bi)
		num_cts = []
		with Pool(processes=6) as p:
			num_cts = list(tqdm(p.imap(worker, zip(samples, itertools.repeat(bi))), total=len(samples)))
		

		num_cts = np.array(num_cts)
		median = np.median(num_cts)
		percentile_10 = np.percentile(num_cts, 10)
		percentile_90 = np.percentile(num_cts, 90)
		print(f'{percentile_10:.1f} - {median:.1f} - {percentile_90:.1f}')
		for i in range(len(samples)):
			cts_req[i] = max(cts_req[i], num_cts[i])
	
	print('==== TOTAL')
	with open('paper_expr/sbox_msb_traces.txt', 'w+') as f:
		for n in cts_req:
			f.write(str(n)+'\n')
	cts_req = np.array(cts_req)
	median = np.median(cts_req)
	percentile_10 = np.percentile(cts_req, 10)
	percentile_90 = np.percentile(cts_req, 90)
	print(f'{percentile_10:.1f} - {median:.1f} - {percentile_90:.1f}')

