from graphql.language.ast import FieldNode, FragmentDefinitionNode, FragmentSpreadNode
from graphql.language.visitor import visit

def get_query_structure(operation, fragments):
    """Flatten the query by resolving all fragments into a single structure."""
    alias_count = {}  # Track alias usage for each field
    def resolve_selection_set(selection_set, resolved_fragments):
        fields = []
        for field in selection_set.selections:
            if isinstance(field, FieldNode):
                field_name = field.name.value
                alias = field.alias.value if field.alias else field_name  # Default alias is the field name

                # Track alias usage for the field (not just for each alias)
                if field_name not in alias_count:
                    alias_count[field_name] = set()  # Set to track unique aliases for a field

                alias_count[field_name].add(alias)

                # Check if alias count exceeds the maximum allowed
                if len(alias_count[field_name]) > 5:  # Example max_aliases = 5
                    raise Exception(f"Too many aliases for the field '{field_name}'")

                # Handle sub-selections (children)
                if field.selection_set:
                    fields.append({
                        "name": alias,
                        "children": resolve_selection_set(field.selection_set, resolved_fragments)
                    })
                else:
                    fields.append({"name": alias, "children": []})
            elif isinstance(field, FragmentSpreadNode):  # Handle fragment references
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
    def __init__(self, max_depth, max_aliases):
        self.max_depth = max_depth
        self.max_aliases = max_aliases  # Set the maximum allowed aliases for fields

    def resolve(self, next_, root, info, **args):
        fragments = info.fragments if hasattr(info, "fragments") else {}
        try:
            # Get the query structure and check alias usage
            structure = get_query_structure(info.operation, fragments)

            # Measure the depth of the query
            depth = measure_depth(structure)

            # Check for max depth
            if depth > self.max_depth:
                raise Exception(f"Query exceeds maximum depth of {self.max_depth}. Actual depth: {depth}")

        except Exception as e:
            raise e  # Raise the alias or depth exception if the limit is exceeded

        return next_(root, info, **args)
