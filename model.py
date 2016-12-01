import abc
import bisect
import decimal
import math
import random

import numpy as np

class Model(metaclass=abc.ABCMeta):
    
    @abc.abstractmethod
    def generate(self): pass

    def sample(self, n):
        return (self.generate() for _ in range(n))

    @abc.abstractmethod
    def logprob(self, word): pass


class PosEstimator:
    
    def __init__(self, sample, realsize=None):
        # realsize is a hack to make plot_restrictions work.
        # don't use unless you know what you're doing!
        self.logprobs = logprobs = np.fromiter((lp for lp, _ in sample), float)
        logprobs.sort()
        if realsize is None:
            realsize = len(logprobs)
        logn = math.log2(realsize)
        self.positions = (2 ** (logprobs - logn)).cumsum()

    def position(self, logprob):
        idx = bisect.bisect_right(self.logprobs, logprob)
        return self.positions[idx - 1] if idx > 0 else 0

    def logpos(self, logprob):
        return math.log2(self.position(logprob))

    def logprob(self, pos):
        return np.interp(math.log2(pos + 1), np.log2(self.positions + 1),
                         self.logprobs)

    def generate(self, model_generate, entropy):
        lp_threshold = self.logprob(2 ** entropy)
        for logprob, word in iter(model_generate, None):
            if (logprob <= lp_threshold and
                lp_threshold < logprob - math.log2(random.random())):
                return logprob, word

    def sample(self, model_generate, entropy, n):
        for _ in range(n):
            yield self.generate(model_generate, entropy)


class IPWEstimator:

    def __init__(self, sample, store=lambda lp, word: (lp, word)):
        sample = list(sample)
        self.logn = logn = math.log2(len(sample))
        self.ipw = [2 ** decimal.Decimal(lp - logn) for lp, _ in sample]
        self.stored = [store(lp, word) for lp, word in sample]

    def evaluate(self, fun):
        return sum(w * fun(v)
                   for w, v in zip(self.ipw, self.stored))
