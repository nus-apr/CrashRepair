# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import typing as t

import attr
from loguru import logger


@attr.s(slots=True, frozen=True, auto_attribs=True)
class ClangAST:
    """Provides access to the Clang AST for a source file.

    Attributes
    ----------
    source_filename: str
        The absolute path of the corresponding source file for this AST
    source: str
        The contents of the source file for this AST
    _ast: t.Dict[str, t.Any]
        The underlying JSON dictionary for the Clang AST
    _line_to_offset: t.Mapping[int, int]
        A mapping from one-indexed line numbers to the zero-indexed position
        of their corresponding newlines, where the first line is mapped to
        -1.
    """
    source_filename: str
    source: str
    _ast: t.Dict[str, t.Any]
    _line_to_offset: t.Mapping[int, int]

    @classmethod
    def load(
        cls,
        ast_filename: str,
        source_filename: str,
    ) -> "ClangAST":
        assert os.path.isabs(source_filename)
        with open(source_filename, "r") as fh:
            source = fh.read()
        line_to_offset = cls._compute_line_to_offset(source)
        with open(ast_filename, "r") as fh:
            return ClangAST(
                source_filename=source_filename,
                source=source,
                ast=json.load(fh),
                line_to_offset=line_to_offset,
            )

    @classmethod
    def _compute_line_to_offset(cls, contents: str) -> t.Mapping[int, int]:
        line_to_offset = {1: -1}
        line = 1
        for offset, char in enumerate(contents):
            # note that we map each line to the newline character that begins the line
            # this allows us to simply add a one-indexed column number to find an offset
            # FIXME does this need to be more robust?
            if char == "\n":
                line += 1
                line_to_offset[line] = offset
        logger.debug("computed line->offset mapping: {}".format(line_to_offset))
        return line_to_offset

    def line_col_to_offset(self, line: int, col: int) -> int:
        """Converts a line and column number in this file to a character offset."""
        assert line >= 1
        assert col >= 1
        return self._line_to_offset[line] + col

    def function_decls(self) -> t.Iterator[t.Dict[str, t.Any]]:
        """Returns an iterator over the top-level function declarations in this AST."""
        # TODO cache these decls
        for decl in self._ast["inner"]:
            if decl["kind"] != "FunctionDecl":
                continue
            if "storageClass" in decl and decl["storageClass"] == "extern":
                continue
            if "loc" not in decl:
                continue
            if "includedFrom" in decl["loc"]:
                continue
            # PROBLEM: patterns/global/float: FunctionDecl loc's don't always include a file attribute!
            # if "file" not in decl["loc"]:
            #     continue
            # if decl["loc"]["file"] == self.source_filename:
            #     yield decl
            yield decl

    def range_encloses_offset(self, range: t.Dict[str, t.Any], offset: int) -> bool:
        """Determines if a given range encloses a given character offset."""
        assert "begin" in range
        assert "end" in range
        assert "offset" in range["begin"]
        assert "offset" in range["end"]
        starts_at = range["begin"]["offset"]
        ends_at = range["end"]["offset"]
        return offset >= starts_at and offset <= ends_at

    def node_encloses_offset(self, node: t.Dict[str, t.Any], offset: int) -> bool:
        """Determines whether a given AST node contains a character at a given offset."""
        assert "range" in node
        return self.range_encloses_offset(node["range"], offset)

    def find_enclosing_function_decl(self, offset: int) -> t.Dict[str, t.Any]:
        """Finds the function declaration that encloses a given character offset."""
        for function_decl in self.function_decls():
            if self.range_encloses_offset(function_decl["range"], offset):
                return function_decl

        raise ValueError("failed to find enclosing function decl at offset {}".format(offset))

    def find_node_at_offset(
        self,
        offset: int,
        root: t.Optional[t.Dict[str, t.Any]] = None,
    ) -> t.Dict[str, t.Any]:
        """Traverses from the root of the AST and finds the first node that begins at a given offset.

        Arguments
        ---------
        offset: int
            the offset at which the AST node must begin
        root
            the root of the AST subtree at which the search should begin

        Raises
        ------
        ValueError
            If no AST node beginning at the provided offset could be found
        """
        if not root:
            root = self.find_enclosing_function_decl(offset)

        if root["range"]["begin"]["offset"] == offset:
            return root

        for child in root.get("inner", []):
            if self.node_encloses_offset(child, offset):
                return self.find_node_at_offset(offset, root=child)

        logger.warning(
            "failed to find AST node that begins at offset [%s]: matching to nearest enclosing node",
            offset,
        )
        return root

    def node_is_stmt(self, node: t.Dict[str, t.Any]) -> bool:
        """Determines whether a given node is considered to be a statement."""
        node_kind = node["kind"]
        if "Stmt" in node_kind:
            return True
        if "Expr" in node_kind:
            return True
        return False

    def find_enclosing_condition(
        self,
        node: t.Dict[str, t.Any],
    ) -> t.Dict[str, t.Any]:
        enclosing_node = node
        ancestors = self.ancestors(node)
        if node["kind"] in ("DoStmt", "ForStmt", "IfStmt", "WhileStmt"):
            if "inner" in node.keys():
                return node["inner"][0]

        for parent in ancestors:
            if parent["kind"] in ("DoStmt", "ForStmt", "IfStmt", "WhileStmt"):
                return enclosing_node
            enclosing_node = parent

        msg = "unable to find enclosing branch condition for AST node: {} ({})"
        msg = msg.format(node["id"], node["kind"])
        raise ValueError(msg)

    def find_enclosing_canonical_stmt(self, node: t.Dict[str, t.Any]) -> t.Dict[str, t.Any]:
        canonical_node = node
        ancestors = self.ancestors(node)

        while ancestors:
            parent = ancestors.pop(0)
            if parent["kind"] == "CompoundStmt":
                return canonical_node
            canonical_node = parent

        msg = "unable to find enclosing canonical statement for AST node: {} ({})"
        msg = msg.format(node["id"], node["kind"])
        raise ValueError(msg)

    def parent(self, node: t.Dict[str, t.Any]) -> t.Dict[str, t.Any]:
        """Returns the parent of a given AST node."""
        return self.ancestors(node)[0]

    def ancestors(
        self,
        node: t.Dict[str, t.Any],
    ) -> t.List[t.Dict[str, t.Any]]:
        node_id = node["id"]
        starts_at = node["range"]["begin"]["offset"]
        function_decl = self.find_enclosing_function_decl(starts_at)
        return self._find_ancestors(function_decl, node_id, starts_at)

    def _find_ancestors(
        self,
        root: t.Dict[str, t.Any],
        node_id: str,
        node_starts_at: int,
    ) -> t.List[t.Dict[str, t.Any]]:
        if root["id"] == node_id:
            return []

        assert "inner" in root
        for child in root["inner"]:
            if self.node_encloses_offset(child, node_starts_at):
                ancestors = self._find_ancestors(child, node_id, node_starts_at)
                ancestors.append(root)
                return ancestors

        raise ValueError("failed to find ancestors of AST node: {}".format(node_id))


