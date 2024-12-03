from typing import List,Dict,Union

from collections import Counter
from defender2yara.defender.signature.hstr import HStrSig,HStrExtSig
from defender2yara.util.utils import all_elements_equal

from .strings import YaraString

class YaraCondition:
    def __init__(self,strings:List[YaraString],signature:Union[HStrSig,HStrExtSig],filesize_check:str,do_header_check:bool=False):
        self.threshold = signature.threshold
        self.strings = strings
        self.signature = signature
        self.do_header_check = do_header_check
        self.filesize_check = filesize_check
        self.statements:List[Union[str,List[str]]] = [] # all state is connected with "and"
        self.compose_logical_expression()

    def compose_logical_expression(self):
        positive_weight_list = [string.weight for string in self.strings if string.weight > 0]
        positive_weight_sum = sum(positive_weight_list)

        # add filesize check to improve the scan performance
        if self.filesize_check:
            self.statements.append(f"filesize < {self.filesize_check}")

        # add file header check to improve the scan performance
        if self.do_header_check:
            if "PEHSTR" in self.signature.sig_type or "DOSHSTR" in self.signature.sig_type:
                self.statements.append("uint16(0) == 0x5a4d")
            elif "MACHOHSTR" in self.signature.sig_type:
                self.statements.append(
                    "(uint32(0) == 0xfeedfacf) or "
                    "(uint32(0) == 0xcffaedfe) or "
                    "(uint32(0) == 0xfeedface) or "
                    "(uint32(0) == 0xcefaedfe)"
                ) 
            elif "ELFHSTR" in self.signature.sig_type:
                self.statements.append("uint32(0) == 0x464c457f")

        # to simplify the problem, formulate the condition to exclude any of elements with negative weights.
        if min([string.weight for string in self.strings]) < 0:
            self.statements.append("not (any of ($n*))")

        # solve simple cases
        if self.threshold >= positive_weight_sum:
            self.statements.append("all of ($x*)")
            return
        elif all_elements_equal(positive_weight_list) and self.threshold != positive_weight_sum:
            self.statements.append(f"{(self.threshold + positive_weight_list[0] - 1)//positive_weight_list[0]} of ($x*)")
            return

        # solve complex cases
        statements_or:List[str] = []
        positive_weight_map = dict(sorted(Counter(positive_weight_list).items(), key=lambda x: x[0], reverse=True))
        subsets = self.generate_subsets(positive_weight_map,self.threshold)
        for subset in subsets:
            _tmp = []
            weight_count = Counter(subset)
            for w,cnt in weight_count.items():
                _tmp.append(f"{cnt} of ($x_{w}_*)")
            condition = "(" + " and ".join(_tmp) + ")"
            statements_or.append(condition)
        statements_or.append("all of ($x*)") # to avoid yara compile error
        self.statements.append(statements_or)

    
    @staticmethod
    def generate_subsets(weight_map: Dict[int, int], threshold: int) -> List[List[int]]:
        """
        Generate all subsets of weights that meet or exceed the given threshold, 
        without including supersets of already valid subsets.

        This function uses a backtracking algorithm to generate all possible subsets
        of weights from the given weight map, where the sum of weights in each subset
        is greater than or equal to the specified threshold. It includes all minimal
        subsets that meet the threshold, but excludes any superset of an already 
        included subset.

        Args:
            weight_map (Dict[int, int]): A dictionary mapping weights to their counts.
            threshold (int): The minimum sum of weights required for a valid subset.

        Returns:
            List[List[int]]: A list of all valid subsets, where each subset is 
                            represented as a list of weights. If a subset meets the
                            threshold, no superset of it will be included in the result.

        Example:
            >>> weight_map = {5: 2, 3: 1, 2: 2, 1: 1}
            >>> threshold = 7
            >>> generate_subsets(weight_map, threshold)
            [[5, 5], [5, 3], [5, 2, 2]]
            # Note: [5, 5, 1] is not included as [5, 5] already meets the threshold
        """
        # Get lists of keys (weights) and values (counts) from the dictionary
        weight_values = list(weight_map.keys())
        weight_counts = list(weight_map.values())

        def backtrack(index: int, current_subset: List[int], subsets: List[List[int]]):
            """
            Helper function to generate all subsets using backtracking with pruning.

            This function implements a depth-first search with backtracking to generate
            all valid subsets. It uses two key pruning strategies to optimize the search:

            1. Early termination: If the current subset sum meets or exceeds the threshold,
            we add it to the result (if valid) and stop exploring further additions.

            2. Subset pruning: If we find a valid subset, we skip adding any elements
            that would create a superset of an already valid subset. This prevents
            generating redundant supersets.

            Args:
                index (int): Current index in the weight_values list.
                current_subset (List[int]): The current subset being built.
                subsets (List[List[int]]): List to store all valid subsets.

            Note:
                The function modifies the 'subsets' list in-place to collect valid subsets.
                It uses recursion to explore all possible combinations of weights.
            """
            # If the sum of the current subset meets or exceeds the threshold
            if sum(current_subset) >= threshold:
                # Don't add if a subset that sums to the threshold has already been found
                if sum(current_subset) - current_subset[-1] >= threshold:
                    return
                subsets.append(current_subset.copy())
                return

            # If we've reached the end of the weight list, return
            if index == len(weight_values):
                return

            # Case 1: Don't include the current weight
            backtrack(index + 1, current_subset, subsets)

            # Case 2: Include the current weight (up to its count)
            for _ in range(weight_counts[index]):
                current_subset.append(weight_values[index])
                backtrack(index + 1, current_subset, subsets)

            # Restore the original state (backtrack)
            for _ in range(weight_counts[index]):
                current_subset.pop()

        # List to store all valid subsets
        all_subsets = []
        backtrack(0, [], all_subsets)
        return all_subsets