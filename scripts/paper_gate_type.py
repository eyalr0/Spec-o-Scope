from matplotlib import pyplot as plt
import numpy as np
import seaborn as sns
from consts import ADJ_FACTOR

REPEAT_COUNT = 100_000
SAMPLE_COUNT = 1260
data_titles = []
data_values = []
with open('paper_expr/gate_type.txt', 'r') as f:
	lines = iter(f)
	try:
		while True:
			title = next(lines)[:-1]
			values = [int(next(lines)[:-1])*ADJ_FACTOR/SAMPLE_COUNT for _ in range(REPEAT_COUNT)]
			data_titles.append(title)
			data_values.append(values)
			print(f'{title} median: {np.median(values):.2f}')
	except StopIteration:
		pass

ax = sns.boxplot(data_values, showfliers=False)
ax.set_xticklabels(data_titles)
ax.set_ylim(bottom=0)
plt.ylabel('cycles')
plt.savefig('paper_expr/gate_type.png')
plt.close()