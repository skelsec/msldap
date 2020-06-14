#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .drawing import BoxStyle
from .traversal import DictTraversal
from .util import KeyArgsConstructor


class LeftAligned(KeyArgsConstructor):
    """Creates a renderer for a left-aligned tree.

    Any attributes of the resulting class instances can be set using
    constructor arguments."""

    draw = BoxStyle()
    "The draw style used. See :class:`~asciitree.drawing.Style`."
    traverse = DictTraversal()
    "Traversal method. See :class:`~asciitree.traversal.Traversal`."

    def render(self, node):
        """Renders a node. This function is used internally, as it returns
        a list of lines. Use :func:`~asciitree.LeftAligned.__call__` instead.
        """
        lines = []

        children = self.traverse.get_children(node)
        lines.append(self.draw.node_label(self.traverse.get_text(node)))

        for n, child in enumerate(children):
            child_tree = self.render(child)

            if n == len(children) - 1:
                # last child does not get the line drawn
                lines.append(self.draw.last_child_head(child_tree.pop(0)))
                lines.extend(self.draw.last_child_tail(l)
                             for l in child_tree)
            else:
                lines.append(self.draw.child_head(child_tree.pop(0)))
                lines.extend(self.draw.child_tail(l)
                             for l in child_tree)

        return lines

    def __call__(self, tree):
        """Render the tree into string suitable for console output.

        :param tree: A tree."""
        return '\n'.join(self.render(self.traverse.get_root(tree)))


# legacy support below

from .drawing import Style
from .traversal import Traversal


class LegacyStyle(Style):
    def node_label(self, text):
        return text

    def child_head(self, label):
        return '  +--' + label

    def child_tail(self, line):
        return '  |' + line

    def last_child_head(self, label):
        return '  +--' + label

    def last_child_tail(self, line):
        return '   ' + line


def draw_tree(node,
              child_iter=lambda n: n.children,
              text_str=str):
    """Support asciitree 0.2 API.

    This function solely exist to not break old code (using asciitree 0.2).
    Its use is deprecated."""
    return LeftAligned(traverse=Traversal(get_text=text_str,
                                          get_children=child_iter),
                       draw=LegacyStyle())(node)
