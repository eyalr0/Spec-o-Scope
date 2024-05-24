from matplotlib import pyplot as plt
import seaborn as sns
import numpy as np

dat = [[int(y) for y in x[:-2].split(' ')] for x in open('paper_expr/min_distinguish.txt').readlines()]
attacker1 = np.array([x[:120] for x in dat])
attacker2 = np.array([x[120:] for x in dat])

def process_data(data):
	BOUND = np.max(data) + 1
	acc = np.zeros((data.shape[1], BOUND))
	for i in range(data.shape[1]):
		for j in data[:, i]:
			if j < 0:
				continue
			acc[i, j] += 1
		acc[i, :] /= np.sum(acc[i, :])
	return acc

def plot_data(acc, xjump=6):
	ticks = list(range(0, acc.shape[1], xjump))
	xlabels = [None]*(min(len(ticks)*xjump, acc.shape[1]))
	xlabels[::xjump] = ticks
	sns.heatmap(acc, xticklabels=xlabels)
	plt.xlabel("Sample detection index")
	plt.ylabel("Wait duration in cycles")

# acc1 = process_data(attacker1)
# plot_data(acc1)
# plt.savefig(f'paper_expr/min_distinguish_a1.png')
# plt.close()

acc2 = process_data(attacker2)
plot_data(acc2[30:81,10:21], xjump=2)
# plot_data(acc2)
plt.savefig(f'paper_expr/min_distinguish_a2.png')
plt.close()