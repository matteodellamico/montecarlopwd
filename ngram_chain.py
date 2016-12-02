# Copyright 2016 Symantec Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0

import bisect
import bz2
import collections
import heapq
import itertools
import math
import operator
import pickle
import random
import shelve

import numpy as np

import model

__default = object()


def default_start(n):
    return '\0' * (n - 1)


def ngrams(word, n, start=__default, end='\0'):
    if start is __default:
        start = default_start(n)
    word = start + word + end
    return [word[i:i + n] for i in range(len(word) - n + 1)]


def ngrams_counter(words, n, start=__default, end='\0', with_counts=False):
    if start is __default:
        start = default_start(n)
    if not with_counts:
        words = ((1, w) for w in words)
    res = collections.defaultdict(itertools.repeat(0).__next__)
    for count, word in words:
        word = start + word + end
        for i in range(len(word) - n + 1):
            res[word[i:i + n]] += count
    return res


def parse_textfile(fname='/usr/share/dict/words'):
    try:
        with open(fname) as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        with bz2.open('{}.bz2'.format(fname)) as f:
            return [line.decode('latin9').strip() for line in f]


def parse_rockyou(fname='datasets/rockyou-withcount.txt.bz2'):
    res = []
    with bz2.open(fname) as f:
        lines = (line.rstrip() for line in f)
        for l in lines:
            if len(l) < 8 or l[7] != 32:
                continue
            try:
                res.append((int(l[:7]), l[8:].decode('utf-8')))
            except UnicodeDecodeError:
                continue
    return res

Node = collections.namedtuple('Node', 'transitions cumprobs logprobs')


class NGramModel(model.Model):

    def setup_nodes(self, shelfname, flags='c'):
        self.shelfname = shelfname
        if shelfname is None:
            return {}
        else:
            return shelve.open(shelfname, flags,
                               protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def get_from_shelf(cls, shelfname, *args, **kwargs):
        return cls([], *args, shelfname=shelfname, **kwargs)

    def __init__(self, words, n, with_counts=False, shelfname=None):
        self.start = start = default_start(n)
        self.end = end = '\0'
        transitions = collections.defaultdict(list)
        for ngram, count in ngrams_counter(words, n, start, end,
                                           with_counts).items():
            state, transition = ngram[:-1], ngram[-1]
            transitions[state].append((count, transition))

        flags = 'c' if words else 'r'
        self.nodes = nodes = self.setup_nodes(shelfname, flags)
        for state, ctlist in transitions.items():
            ctlist.sort(reverse=True, key=operator.itemgetter(0))
            total = sum(c for c, _ in ctlist)
            transitions, cumprobs, logprobs = [], [], []
            cum_counts = 0
            for count, transition in ctlist:
                cum_counts += count
                transitions.append(transition)
                cumprobs.append(cum_counts / total)
                logprobs.append(-math.log2(count / total))
            nodes[state] = Node(''.join(transitions),
                                np.array(cumprobs),
                                np.array(logprobs))

    def __del__(self):
        if self.shelfname is not None:
            self.nodes.close()

    def update_state(self, state, transition):
        return (state + transition)[1:]

    def __iter__(self, threshold=float('inf')):

        nodes = self.nodes
        startnode = nodes[self.start]
        # queue items: logprob, word, state, node, node_logprob, index
        queue = [(startnode.logprobs[0], '', self.start, startnode, 0, 0)]

        while queue:
            logprob, word, state, node, node_lp, idx = heapq.heappop(queue)
            transition = node.transitions[idx]
            if transition == self.end:
                yield logprob, word
            else:
                # push new node
                new_state = self.update_state(state, transition)
                new_node = nodes[new_state]
                new_logprob = logprob + new_node.logprobs[0]
                if new_logprob <= threshold:
                    new_item = (new_logprob, word + transition, new_state,
                                new_node, logprob, 0)
                    heapq.heappush(queue, new_item)
            try:
                next_lp = node_lp + node.logprobs[idx + 1]
            except IndexError:
                # we're done exploring this node
                continue
            if next_lp <= threshold:
                # push the next transition in the current node
                next_item = (next_lp, word, state, node, node_lp, idx + 1)
                heapq.heappush(queue, next_item)

    def generate(self, maxlen=100):
        word = []
        state = self.start
        logprob = 0
        for _ in range(maxlen):
            node = self.nodes[state]
            idx = bisect.bisect_left(node.cumprobs, random.random())
            transition = node.transitions[idx]
            logprob += node.logprobs[idx]
            if transition == self.end:
                break
            state = self.update_state(state, transition)
            word.append(transition)
        return logprob, ''.join(word)

    def logprob(self, word, leaveout=False):
        if leaveout:
            raise NotImplementedError
        state = self.start
        res = 0
        for c in word + self.end:
            node = self.nodes[state]
            try:
                idx = node.transitions.index(c)
            except ValueError:
                return float('inf')
            res += node.logprobs[idx]
            state = self.update_state(state, c)
        return res

    def generate_by_threshold(self, threshold, lower_threshold=0, maxlen=100):

        # Efficient generation of passwords -- Ma et al., S&P 2014
        nodes = self.nodes
        start = self.start

        # stack items: node, word, state, logprob, index
        stack = [[nodes[start], '', start, 0, 0]]
        while stack:
            node, word, state, logprob, idx = top = stack[-1]
            try:
                newprob = logprob + node.logprobs[idx]
            except IndexError:
                stack.pop()
                continue
            if newprob > threshold:
                stack.pop()
                continue
            transition = node.transitions[idx]
            if transition == self.end:
                if newprob >= lower_threshold:
                    yield newprob, word
            elif len(stack) == maxlen:
                stack.pop()
                continue
            else:
                newstate = self.update_state(state, transition)
                stack.append([nodes[newstate], word + transition, newstate,
                              newprob, 0])
            # set the new index
            top[4] += 1


class TextGenerator(NGramModel):

    def __init__(self, phrases, n, with_counts=False, shelfname=None):
        self.start = start = ('',) * (n - 1)
        self.end = end = ('',)
        transitions = collections.defaultdict(list)
        for ngram, count in ngrams_counter(phrases, n, start, end,
                                           with_counts).items():
            state, transition = ngram[:-1], ngram[-1]
            transitions[state].append((count, transition))

        flags = 'c' if phrases else 'r'
        self.nodes = nodes = self.setup_nodes(shelfname, flags)
        for state, ctlist in transitions.items():
            ctlist.sort(reverse=True, key=operator.itemgetter(0))
            total = sum(c for c, _ in ctlist)
            transitions, cumprobs, logprobs = [], [], []
            cum_counts = 0
            for count, transition in ctlist:
                cum_counts += count
                transitions.append(transition)
                cumprobs.append(cum_counts / total)
                logprobs.append(-math.log2(count / total))
            transitions = [(t,) for t in transitions]
            nodes[state] = Node(transitions,
                                np.array(cumprobs),
                                np.array(logprobs))

    def generate(self, maxlen=100):
        phrase = ''
        state = self.start
        logprob = 0
        for _ in range(maxlen):
            node = self.nodes[state]
            idx = bisect.bisect_left(node.cumprobs, random.random())
            transition = node.transitions[idx]
            logprob += node.logprobs[idx]
            if transition == self.end:
                break
            state = self.update_state(state, transition)
            if phrase and transition[0][0].isalpha():
                phrase += ' '
            phrase += transition[0]
        return logprob, phrase
