import matplotlib
import matplotlib.pyplot as plt
import numpy as np


labels = ['1', '2', '3', '4', '5']
shared_mem_means = [1.9,
                    130.3,
                    1180,
                    1208,
                    43462]
message_passing_means = [1.9,
                         52.7,
                         513.1,
                         323.3,
                         12013]
lab2_means = [3.3,
              2.6,
              3891,
              2461,
              85717]

x = np.arange(len(labels))  # the label locations
width = 0.35  # the width of the bars

fig, ax = plt.subplots()
rects1 = ax.bar(x - width, shared_mem_means, width, label='shared-mem')
rects2 = ax.bar(x, message_passing_means, width, label='message-passing')
rects3 = ax.bar(x + width, lab2_means, width, label='lab2')

# Add some text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('Average time (ms)')
ax.set_title('Average time on each test case for solutions')
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.set_yscale('log')
ax.legend()

# fig.tight_layout()
fig.savefig('average_times.png')