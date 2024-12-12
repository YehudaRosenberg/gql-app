from graphql.language.ast import FieldNode, FragmentDefinitionNode, FragmentSpreadNode
from graphql.language.visitor import visit

def get_query_structure(operation, fragments):
    """Flatten the query by resolving all fragments into a single structure."""
    def resolve_selection_set(selection_set, resolved_fragments):
        fields = []
        for field in selection_set.selections:
            if isinstance(field, FieldNode):
                if field.selection_set:
                    fields.append({
                        "name": field.name.value,
                        "children": resolve_selection_set(field.selection_set, resolved_fragments)
                    })
                else:
                    fields.append({"name": field.name.value, "children": []})
            elif isinstance(field, FragmentSpreadNode):
                fragment_name = field.name.value
                if fragment_name in resolved_fragments:
                    fields.extend(resolved_fragments[fragment_name])
        return fields

    # Resolve all fragments into a flat dictionary
    resolved_fragments = {
        name: resolve_selection_set(fragment.selection_set, {})
        for name, fragment in fragments.items()
        if isinstance(fragment, FragmentDefinitionNode)
    }

    # Resolve the operation's selection set
    return resolve_selection_set(operation.selection_set, resolved_fragments)

def measure_depth(fields, level=1):
    """Measure depth of the resolved query structure."""
    if not fields:
        return level
    return max(measure_depth(field["children"], level + 1) for field in fields)

class DepthAnalysisMiddleware:
    def __init__(self, max_depth):
        self.max_depth = max_depth

    def resolve(self, next_, root, info, **args):
        fragments = info.fragments if hasattr(info, "fragments") else {}
        structure = get_query_structure(info.operation, fragments)
        depth = measure_depth(structure)
        if depth > self.max_depth:
            raise Exception(
                f"Query exceeds maximum depth of {self.max_depth}. Actual depth: {depth}"
            )
        return next_(root, info, **args)
