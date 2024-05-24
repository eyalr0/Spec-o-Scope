import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

with open('paper_expr/sbox_msb_traces.txt', 'r') as f:
	cts_req = [int(x) for x in f.readlines()]

def get_percentile(a, n):
	return (np.array(a)<=n).mean()

sns.kdeplot(cts_req, cumulative=True)
plt.xlabel('Number of traces')
plt.ylabel('Success rate')
plt.xlim((0, 2000))
plt.yticks([0, .25, .5, .75, 1], ['0%', '25%', '50%', '75%', '100%'])
plt.savefig('paper_expr/sbox_msb_traces.png')
plt.close()

print(f'Success with 1000 ciphertexts: {100*get_percentile(cts_req, 1000)}%')
print(f'Success with 2000 ciphertexts: {100*get_percentile(cts_req, 2000)}%')
