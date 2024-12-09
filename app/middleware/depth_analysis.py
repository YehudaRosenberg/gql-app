from graphql.execution import MiddlewareManager
from graphql.language.ast import FieldNode


def measure_depth(selection_set, level=1):
    max_depth = level
    for field in selection_set.selections:
        if isinstance(field, FieldNode) and field.selection_set:
            new_depth = measure_depth(field.selection_set, level=level + 1)
            if new_depth > max_depth:
                max_depth = new_depth
    return max_depth


class DepthAnalysisMiddleware:
    def __init__(self, max_depth):
        self.max_depth = max_depth

    def resolve(self, next_, root, info, **args):
        depth = measure_depth(info.operation.selection_set)
        if depth > self.max_depth:
            raise Exception(f"Query exceeds maximum depth of {self.max_depth}. Actual depth: {depth}")
        return next_(root, info, **args)
