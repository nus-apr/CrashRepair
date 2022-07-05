# -*- coding: utf-8 -*-
from __future__ import annotations

import abc
import difflib
import json
import os
import typing as t

import attr
from loguru import logger

from .ast import ClangAST
from .localization import FixLocation


@attr.s(frozen=True)
class Mutation(abc.ABC):
    """Describes a single mutation contained within a supermutant."""
    instruction_id = attr.ib(type=int)
    mutant_id = attr.ib(type=int)

    @classmethod
    def from_dict(cls, d: t.Dict[str, t.Any]) -> "Mutation":
        operator = d["operator"]
        name_to_class: t.Mapping[str, t.Type[Mutation]] = {
            "GuardStatement": GuardStatementMutation,
            "InsertConditionalReturn": InsertConditionalReturnMutation,
            "StrengthenBranchCondition": StrengthenBranchConditionMutation,
        }
        return name_to_class[operator]._from_dict(d)

    @classmethod
    @abc.abstractmethod
    def _from_dict(cls, d: t.Dict[str, t.Any]) -> "Mutation":
        ...

    @classmethod
    def load_all(cls, filename: str) -> t.Sequence["Mutation"]:
        if not os.path.exists(filename):
            m = "failed to load mutation index []: not found"
            m = m.format(filename)
            raise ValueError(m)

        with open(filename, "r") as fh:
            return [cls.from_dict(d) for d in json.load(fh)]

    def env(self) -> t.Dict[str, str]:
        """Generates an environment for enabling this mutation."""
        env_var_name = "LLVMREPAIR_INSTRUCTION_MUTANT_{}".format(self.instruction_id)
        env_var_val = str(self.mutant_id)
        return {env_var_name: env_var_val}

    @abc.abstractmethod
    def _apply(
        self,
        ast: ClangAST,
        location: FixLocation
    ) -> str:
        """Non-destructively applies this mutation to a given AST.

        Arguments
        ---------
        ast: ClangAST
            The AST (and source code) for the mutated file
        location: FixLocation
            A description of the IR location at which the mutation was performed

        Returns
        -------
        str
            The mutated source code of the modified source file.
        """
        ...

    def diff(
        self,
        ast: ClangAST,
        location: FixLocation,
        save_to: str,
    ) -> None:
        """Transforms this mutation into a diff.

        Arguments
        ---------
        ast: ClangAST
            The AST (and source code) for the mutated file
        location: FixLocation
            A description of the IR location at which the mutation was performed
        save_to: str
            The path to the file where the diff should be saved.
        """
        original_source = ast.source
        modified_source = self._apply(ast, location)

        diff = difflib.unified_diff(
            original_source.splitlines(True),
            modified_source.splitlines(True),
            fromfile=ast.source_filename,
            tofile=ast.source_filename,
        )

        with open(save_to, "w") as fh:
            fh.writelines(diff)


@attr.s(frozen=True)
class GuardStatementMutation(Mutation):
    constraint_as_source = attr.ib(type=str)
    close_after_instruction_id = attr.ib(type=int)
    close_after_column = attr.ib(type=int)
    close_after_line = attr.ib(type=int)

    @classmethod
    def _from_dict(cls, d: t.Dict[str, t.Any]) -> "Mutation":
        if d["close-after"]["implicit"]:
            raise ValueError("attempted to close guard statement at implicit location")

        return GuardStatementMutation(
            mutant_id=d["id"],
            instruction_id=d["instruction"],
            constraint_as_source=d["constraint-as-source"],
            close_after_instruction_id=d["close-after"]["instruction-id"],
            close_after_column=d["close-after"]["column"],
            close_after_line=d["close-after"]["line"],
        )

    def _apply(
        self,
        ast: ClangAST,
        location: FixLocation,
    ) -> str:
        logger.debug("performing guard statement mutation at fix location: {}".format(location))

        # find the AST node corresponding to the fix location
        fix_node_starts_at = ast.line_col_to_offset(location.line, location.column)
        fix_node = ast.find_node_at_offset(fix_node_starts_at)
        logger.debug("found AST node for fix location: {}".format(fix_node))

        is_decl_included = False
        child_node_list = [fix_node]
        while child_node_list:
            iterate_node = child_node_list.pop()
            if iterate_node["kind"] == "DeclRefExpr":
                is_decl_included = True
                break
            if "inner" in iterate_node.keys():
                for child_node in iterate_node["inner"]:
                    child_node_list.append(child_node)

        if is_decl_included:
            # TODO: split declaration and initialization
            logger.debug("[WARNING] found variable declaration inside the guard (maybe referenced later)")

        # find the enclosing canonical stmt
        fix_stmt = ast.find_enclosing_canonical_stmt(fix_node)
        logger.debug("found enclosing stmt for fix location: {}".format(fix_stmt["id"]))

        # find the AST node corresponding to the location at which the closing brace should be placed
        # FIXME corner case: VarDecl requires special handling!
        close_after_node_at = ast.line_col_to_offset(
            self.close_after_line,
            self.close_after_column,
        )
        close_after_node = ast.find_node_at_offset(close_after_node_at)
        logger.debug("found AST node for closing location: {}".format(close_after_node["id"]))

        # find the enclosing canonical statement after which we should inject the closing brace
        close_after_stmt = ast.find_enclosing_canonical_stmt(close_after_node)
        logger.debug("found enclosing stmt for closing location: {}".format(close_after_stmt["id"]))

        # escape the dangerous code!
        insert_escape_at = fix_stmt["range"]["begin"]["offset"]
        close_escape_at = close_after_stmt["range"]["end"]["offset"] + 1

        fixed_source = "{}\nif ({}) {{\n{}\n}}\n{}"
        fixed_source = fixed_source.format(
            ast.source[:insert_escape_at],
            self.constraint_as_source,
            ast.source[insert_escape_at:close_escape_at],
            ast.source[close_escape_at:],
        )
        return fixed_source


@attr.s(frozen=True)
class StrengthenBranchConditionMutation(Mutation):
    constraint_as_source = attr.ib(type=str)

    @classmethod
    def _from_dict(cls, d: t.Dict[str, t.Any]) -> "Mutation":
        return StrengthenBranchConditionMutation(
            mutant_id=d["id"],
            instruction_id=d["instruction"],
            constraint_as_source=d["constraint-as-source"],
        )

    def _apply(
        self,
        ast: ClangAST,
        location: FixLocation
    ) -> str:
        logger.debug("performing strengthen branch mutation at fix location: {}".format(location))

        # find the AST node corresponding to the fix location
        fix_node_starts_at = ast.line_col_to_offset(location.line, location.column)
        fix_node = ast.find_node_at_offset(fix_node_starts_at)
        logger.debug("found AST node for fix location: {}".format(fix_node["id"]))

        # find the AST node for the enclosing condition
        enclosing_condition = ast.find_enclosing_condition(fix_node)
        logger.debug("found enclosing branch condition: {}".format(enclosing_condition["id"]))

        # for debugging purposes, find the enclosing stmt
        enclosing_stmt = ast.parent(enclosing_condition)
        logger.debug("found enclosing stmt: {}".format(enclosing_stmt["id"]))

        # inject the repair immediately before the existing condition
        insert_repair_at = enclosing_condition["range"]["begin"]["offset"]
        fixed_source = "{}{} && {}".format(
            ast.source[:insert_repair_at],
            self.constraint_as_source,
            ast.source[insert_repair_at:],
        )
        return fixed_source


@attr.s(frozen=True)
class InsertConditionalReturnMutation(Mutation):
    constraint_as_source = attr.ib(type=str)
    return_value_as_source = attr.ib(type=str)

    @classmethod
    def _from_dict(cls, d: t.Dict[str, t.Any]) -> "Mutation":
        return InsertConditionalReturnMutation(
            mutant_id=d["id"],
            instruction_id=d["instruction"],
            constraint_as_source=d["constraint-as-source"],
            return_value_as_source=d.get("return-value-as-source", ""),
        )

    def _apply(
        self,
        ast: ClangAST,
        location: FixLocation
    ) -> str:
        logger.debug("inserting conditional return mutation at fix location: {}".format(location))

        # find the AST node corresponding to the fix location
        fix_node_starts_at = ast.line_col_to_offset(location.line, location.column)
        fix_node = ast.find_node_at_offset(fix_node_starts_at)
        logger.debug("found AST node for fix location: {}".format(fix_node["id"]))

        # find the enclosing canonical stmt
        fix_stmt = ast.find_enclosing_canonical_stmt(fix_node)
        logger.debug("found enclosing stmt for fix location: {}".format(fix_stmt["id"]))

        # find the location at which the canonical stmt begins
        fix_stmt_starts_at = fix_stmt["range"]["begin"]["offset"]

        # inject the repair immediately before the fix stmt
        fixed_source = "{} if (!{}) {{ return {}; }}\n{}"
        fixed_source = fixed_source.format(
            ast.source[:fix_stmt_starts_at],
            self.constraint_as_source,
            self.return_value_as_source,
            ast.source[fix_stmt_starts_at:],
        )
        return fixed_source

