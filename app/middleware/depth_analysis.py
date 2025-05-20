# app/middleware/depth_analysis.py
from graphql.language.ast import (
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    OperationDefinitionNode,
    SelectionSetNode,
)
import logging

log = logging.getLogger(__name__)

# Note on Depth Calculation used in this middleware:
# The `measure_depth` function calculates depth as the actual number of nesting levels.
# - `query { fieldA }` (1 actual nesting level) will have a measured depth of 1.
# - `query { fieldA { fieldB } }` (2 actual nesting levels) will have a measured depth of 2.
# If the server's configured `self.max_depth` is 5, it allows up to 5 actual nesting levels.
# The check `actual_query_depth > self.max_depth` correctly compares these values.

def _resolve_selection_set_recursively(
        selection_set_ast: SelectionSetNode,
        fragment_ast_node_map: dict,
        resolved_fragment_structures_cache: dict,
        field_alias_counts_ref: dict,
        max_aliases_per_field: int,
        current_resolution_path: set
) -> list:
    """
    Recursively resolves a selection set, inlining fragments and counting aliases.
    (Implementation from previous response - remains the same)
    """
    fields_structure = []
    if not selection_set_ast:
        return fields_structure

    for selection_node in selection_set_ast.selections:
        if isinstance(selection_node, FieldNode):
            original_field_name = selection_node.name.value
            alias = selection_node.alias.value if selection_node.alias else original_field_name

            if original_field_name not in field_alias_counts_ref:
                field_alias_counts_ref[original_field_name] = set()
            field_alias_counts_ref[original_field_name].add(alias)

            if len(field_alias_counts_ref[original_field_name]) > max_aliases_per_field:
                raise ValueError(
                    f"Too many aliases for the field '{original_field_name}'. "
                    f"Limit is {max_aliases_per_field}, "
                    f"found {len(field_alias_counts_ref[original_field_name])} "
                    f"unique aliases: {sorted(list(field_alias_counts_ref[original_field_name]))}."
                )

            sub_fields_structure = []
            if selection_node.selection_set:
                sub_fields_structure = _resolve_selection_set_recursively(
                    selection_set_ast=selection_node.selection_set,
                    fragment_ast_node_map=fragment_ast_node_map,
                    resolved_fragment_structures_cache=resolved_fragment_structures_cache,
                    field_alias_counts_ref=field_alias_counts_ref,
                    max_aliases_per_field=max_aliases_per_field,
                    current_resolution_path=current_resolution_path,
                )
            fields_structure.append({"name": alias, "children": sub_fields_structure})

        elif isinstance(selection_node, FragmentSpreadNode):
            fragment_name = selection_node.name.value

            if fragment_name in current_resolution_path:
                raise ValueError(
                    f"Circular fragment reference detected: Fragment '{fragment_name}' "
                    f"is spread within its own resolution path ({' -> '.join(list(current_resolution_path))} -> {fragment_name})."
                )

            if fragment_name not in resolved_fragment_structures_cache:
                if fragment_name not in fragment_ast_node_map:
                    raise ValueError(f"Fragment '{fragment_name}' was spread but not defined.")

                fragment_def_node = fragment_ast_node_map[fragment_name]

                new_resolution_path = current_resolution_path.copy()
                new_resolution_path.add(fragment_name)

                resolved_fragment_structures_cache[fragment_name] = _resolve_selection_set_recursively(
                    selection_set_ast=fragment_def_node.selection_set,
                    fragment_ast_node_map=fragment_ast_node_map,
                    resolved_fragment_structures_cache=resolved_fragment_structures_cache,
                    field_alias_counts_ref=field_alias_counts_ref,
                    max_aliases_per_field=max_aliases_per_field,
                    current_resolution_path=new_resolution_path,
                )

            if fragment_name in resolved_fragment_structures_cache:
                fields_structure.extend(resolved_fragment_structures_cache[fragment_name])

        elif isinstance(selection_node, InlineFragmentNode):
            inline_fragment_fields_structure = _resolve_selection_set_recursively(
                selection_set_ast=selection_node.selection_set,
                fragment_ast_node_map=fragment_ast_node_map,
                resolved_fragment_structures_cache=resolved_fragment_structures_cache,
                field_alias_counts_ref=field_alias_counts_ref,
                max_aliases_per_field=max_aliases_per_field,
                current_resolution_path=current_resolution_path,
            )
            fields_structure.extend(inline_fragment_fields_structure)

    return fields_structure


def get_query_structure(
        operation_ast_node: OperationDefinitionNode,
        fragment_ast_node_map: dict,
        max_aliases_per_field: int
) -> list:
    """
    Flattens the query by resolving fragments and builds a structure for depth analysis.
    (Implementation from previous response - remains the same)
    """
    field_alias_counts_globally = {}
    resolved_fragment_structures_cache = {}

    for frag_name, frag_def_node in fragment_ast_node_map.items():
        if frag_name not in resolved_fragment_structures_cache:
            resolution_path_for_this_fragment_def = {frag_name}
            resolved_fragment_structures_cache[frag_name] = _resolve_selection_set_recursively(
                selection_set_ast=frag_def_node.selection_set,
                fragment_ast_node_map=fragment_ast_node_map,
                resolved_fragment_structures_cache=resolved_fragment_structures_cache,
                field_alias_counts_ref=field_alias_counts_globally,
                max_aliases_per_field=max_aliases_per_field,
                current_resolution_path=resolution_path_for_this_fragment_def,
            )

    main_query_structure = _resolve_selection_set_recursively(
        selection_set_ast=operation_ast_node.selection_set,
        fragment_ast_node_map=fragment_ast_node_map,
        resolved_fragment_structures_cache=resolved_fragment_structures_cache,
        field_alias_counts_ref=field_alias_counts_globally,
        max_aliases_per_field=max_aliases_per_field,
        current_resolution_path=set(),
    )
    return main_query_structure


def measure_depth(resolved_query_structure: list, current_level_of_parent: int = 0) -> int:
    """
    Measures the depth of the resolved query structure.
    (Implementation from previous response - remains the same)
    """
    if not resolved_query_structure:
        return current_level_of_parent

    max_depth_found = current_level_of_parent + 1

    for field_node_struct in resolved_query_structure:
        if field_node_struct.get("children"):
            depth_of_child_path = measure_depth(
                field_node_struct["children"],
                current_level_of_parent + 1
            )
            if depth_of_child_path > max_depth_found:
                max_depth_found = depth_of_child_path

    return max_depth_found


class DepthAnalysisMiddleware:
    def __init__(self, max_depth: int, max_aliases: int, introspection_max_depth: int = None):
        """
        Middleware to analyze and enforce query depth and alias limits.

        Args:
            max_depth: Max allowed actual nesting depth for general queries.
            max_aliases: Max unique aliases per original field name.
            introspection_max_depth: A specific, potentially more lenient, max depth for
                                     GraphQL introspection queries. If None, defaults to
                                     a value slightly higher than max_depth or a reasonable minimum.
        """
        self.max_depth = max_depth
        self.max_aliases = max_aliases

        if introspection_max_depth is None:
            self.introspection_max_depth = max(self.max_depth, 15) # Example default
        else:
            self.introspection_max_depth = introspection_max_depth

        log.info(
            f"DepthAnalysisMiddleware initialized with max_depth={self.max_depth}, "
            f"max_aliases={self.max_aliases}, "
            f"introspection_max_depth={self.introspection_max_depth}"
        )

    def _is_introspection_query(self, operation_ast_node: OperationDefinitionNode) -> bool:
        """
        Checks if the query is likely an introspection query.
        Looks for top-level fields like `__schema` or `__type`.
        """
        if operation_ast_node and operation_ast_node.selection_set:
            for top_level_selection in operation_ast_node.selection_set.selections:
                if isinstance(top_level_selection, FieldNode):
                    # Common introspection query entry points
                    if top_level_selection.name.value in ("__schema", "__type"):
                        # More precise check: operation name often includes "Introspection"
                        if operation_ast_node.name and "Introspection" in operation_ast_node.name.value:
                            return True
                        return True
        return False

    def resolve(self, next_, root, info, **args):
        if not hasattr(info, "operation") or not isinstance(info.operation, OperationDefinitionNode):
            log.warning("DepthAnalysisMiddleware: 'info.operation' is missing or not an OperationDefinitionNode. Skipping analysis.")
            return next_(root, info, **args)

        operation_ast_node = info.operation
        fragment_ast_node_map = info.fragments if hasattr(info, "fragments") and isinstance(info.fragments, dict) else {}

        try:
            # Determine the effective max depth for this query
            is_introspection = self._is_introspection_query(operation_ast_node)
            effective_max_depth = self.introspection_max_depth if is_introspection else self.max_depth

            if is_introspection:
                log.debug(f"Introspection query detected. Applying max_depth: {effective_max_depth}")
            else:
                log.debug(f"Regular query. Applying max_depth: {effective_max_depth}")


            structure = get_query_structure(
                operation_ast_node=operation_ast_node,
                fragment_ast_node_map=fragment_ast_node_map,
                max_aliases_per_field=self.max_aliases
            )

            actual_query_depth = measure_depth(structure)
            log.debug(f"Calculated query depth: {actual_query_depth} for effective_max_depth: {effective_max_depth}")


            if actual_query_depth > effective_max_depth:
                log.warning(
                    f"Query rejected: Exceeds maximum depth of {effective_max_depth} "
                    f"({'for introspection' if is_introspection else 'for general query'}). "
                    f"Actual depth: {actual_query_depth}."
                )
                raise ValueError( # This will be caught and converted to a GraphQL error by the framework
                    f"Query exceeds maximum depth of {effective_max_depth}. "
                    f"Actual depth: {actual_query_depth}"
                )

        except ValueError as e:
            log.warning(f"Query validation error in DepthAnalysisMiddleware: {e}")
            raise e
        except Exception as e:
            log.error(f"Unexpected error in DepthAnalysisMiddleware: {e}", exc_info=True)
            raise e

        return next_(root, info, **args)