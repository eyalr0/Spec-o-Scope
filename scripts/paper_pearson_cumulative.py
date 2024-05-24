import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

correct = np.array([float(x) for x in open('paper_expr/pearson_correct.txt').readlines()])
incorrect = np.array([float(x) for x in open('paper_expr/pearson_incorrect.txt').readlines()])

# sns.kdeplot({'correct': correct, 'incorrect': incorrect})
# plt.savefig('pearson.png')
# plt.close()

xs = [.01 * x for x in range(101)]
ys_correct = [np.sum(correct < x)/len(correct) for x in xs]
ys_incorrect = [np.sum(incorrect < x)/len(incorrect) for x in xs]
sns.lineplot(x=xs, y=ys_correct, label='correct')
sns.lineplot(x=xs, y=ys_incorrect, label='incorrect')
plt.legend()
plt.xlabel('Pearson Correlation')
plt.ylabel('Cumulative Probability')
plt.savefig('paper_expr/pearson_cumulative.png')
plt.close()