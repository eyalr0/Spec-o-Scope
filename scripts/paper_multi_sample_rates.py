from matplotlib import pyplot as plt
import numpy as np
import seaborn as sns
from consts import ADJ_FACTOR

REPEAT_COUNT = 1_000_000
SAMPLE_COUNT = 1260
data_titles = []
data_values = []
with open('paper_expr/multi_sample_rates.txt', 'r') as f:
	lines = iter(f)
	try:
		while True:
			title = next(lines)[:-1]
			values = [int(next(lines)[:-1])*ADJ_FACTOR/SAMPLE_COUNT for _ in range(REPEAT_COUNT)]
			if 'PS (' in title:	
				continue
			sc = int(title.split('[')[1][:-1])
			values = [x*sc for x in values]
			data_titles.append(title)
			data_values.append(values)
			print(f'{title} median: {np.median(values):.2f}')
	except StopIteration:
		pass

plt.rcParams.update({'font.size': 13})

plt.xlim(left=0, right=11)
plt.xticks(np.arange(1, 11))

rp = sns.regplot(x=list(range(1, 11)), y=[np.median(v) for v in data_values], ci=None, truncate=False)
xs = rp.get_lines()[0].get_xdata()[:2]
ys = rp.get_lines()[0].get_ydata()[:2]
a = (ys[1] - ys[0])/(xs[1] - xs[0])
b = ys[0] - (a * xs[1])
equation = f'y = {a:.2f}x + {b:.2f}'
plt.text(2, 90, equation, fontsize=13, color='black')
# plt.title('Median gate cycles as a function of sample count')
plt.xlabel('Number of scope operations in gate')
plt.ylabel('Cycles')
plt.ylim(bottom=40)
plt.savefig('paper_expr/multi_sample_rates_y40.png')
plt.ylim(bottom=0)
plt.savefig('paper_expr/multi_sample_rates_y0.png')
plt.close()