"""
Plot data for the project
"""

import re
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

pattern = re.compile(r"^a(\d+)n\d+d(\d+)\.pkl$")

datasets = []
for p in Path().glob("*.pkl"):
    m = pattern.match(p.name)
    if not m:
        continue
    algo, d = (int(s) for s in m.groups())
    df = pd.read_pickle(p)
    datasets.append((algo, d, df))

# largest 256 + difficulty 15
a, d, df2 = [d for d in datasets if d[0] == 512 and d[1] == 15][0]
# largest 512 + difficulty 15
a, d, df5 = [d for d in datasets if d[0] == 512 and d[1] == 15][0]

p = 1 / 2 ** 15
x = np.arange(1, df.tries.max())
theo = p * (1 - p) ** (x - 1)


def hist(data, *args, **kwargs):
    """Weighted (normalized) histogram"""
    weights = [np.ones_like(x) / len(x) for x in data]
    plt.hist(data, weights=weights, *args, **kwargs)


plt.plot(x, theo * 292766 / 50, label="theoretical")
hist([df2.tries, df5.tries], label=["SHA-256", "SHA-512"], bins=50, histtype="step")
plt.legend()
plt.yscale("log")
plt.xlabel("Number of attempts")
plt.ylabel("Normalized count")
plt.title("Histogram of attempts to get 15 leading zeros")
plt.savefig("attempts-histogram.png")

hist(
    [df2.time * 1000, df5.time * 1000],
    label=["SHA-256", "SHA-512"],
    bins=50,
    histtype="step",
)
plt.legend()
plt.yscale("log")
plt.xlabel("Time taken [ms]")
plt.ylabel("Normalized count")
plt.title("Histogram of time to get 15 leading zero bits")
plt.savefig("time-histogram.png")


tries2 = list(zip(*sorted([(d, df.tries.mean()) for a, d, df in datasets if a == 256])))
tries5 = list(zip(*sorted([(d, df.tries.mean()) for a, d, df in datasets if a == 512])))
plt.plot(*tries2, label="SHA-256")
plt.plot(*tries5, label="SHA-512")
plt.legend()
plt.yscale("log")
plt.xlabel("Number of leading 0 bits")
plt.ylabel("Mean number of attempts")
plt.title("Attempts vs. Difficulty")
plt.savefig("attempts-v-difficulty.png")

time2 = list(
    zip(*sorted([(d, df.time.mean() * 1000) for a, d, df in datasets if a == 256]))
)
time5 = list(
    zip(*sorted([(d, df.time.mean() * 1000) for a, d, df in datasets if a == 512]))
)
plt.plot(*time2, label="SHA-256")
plt.plot(*time5, label="SHA-512")
plt.legend()
plt.yscale("log")
plt.xlabel("Number of leading 0 bits")
plt.ylabel("Mean time taken [ms]")
plt.title("Time taken vs. Difficulty")
plt.savefig("time-v-difficulty.png")
