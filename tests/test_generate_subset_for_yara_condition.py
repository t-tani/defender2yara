from typing import List,Dict
from collections import Counter
from defender2yara.yara.condition import YaraCondition
from tests.testcases_threshold_and_weights import TEST_CASES


for threshold, weights in TEST_CASES:
    weight_map = dict(sorted(Counter(weights).items(), key=lambda x: x[0], reverse=True))
    subsets = YaraCondition.generate_subsets(weight_map,threshold)
    #print(len(weights),threshold,len(subsets))
    print(f"threshold: {threshold}, weights_size:{len(weights)}")
    for subset in subsets:
        print(sum(subset), subset)


