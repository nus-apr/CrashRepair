#pragma once

#include <iterator>
#include <memory>
#include <vector>

#include <spdlog/spdlog.h>

#include "Mutators.h"

namespace crashrepairfix {

class ExprMutations {
public:
  static ExprMutations generate(
    Expr const *original,
    size_t maxEdits = 1
  ) {
      spdlog::debug("mutating expression [size: {}]: {}", original->size(), original->toString());

    auto mutations = ExprMutations(original, maxEdits);
    mutations.add(std::make_unique<ExprIdentityMutator>());
    mutations.add(std::make_unique<SwapBinOpcodeMutator>());
    spdlog::debug("generated {} mutations", mutations.size());
    return mutations;
  }

  std::vector<std::unique_ptr<Expr>> filter(
    std::function<bool(Expr const *)> predicate,
    size_t limit
  ) {
    spdlog::debug("filtering {} mutations based on satisfiability", size());
    std::vector<size_t> editMask(numNodes, 0);
    std::vector<std::unique_ptr<Expr>> results;
    filter(predicate, limit, 0, 0, editMask, results);
    return results;
  }

  ExprMutations(ExprMutations &&other) noexcept :
    original(other.original),
    maxEdits(other.maxEdits),
    numNodes(other.numNodes),
    nodeEdits(std::move(other.nodeEdits)),
    mutators(std::move(other.mutators))
  {}

  ~ExprMutations(){}

  size_t size() const {
    size_t numEdits = 0;
    for (auto const &editsAtNode : nodeEdits) {
      numEdits += editsAtNode.size();
    }
    return numEdits;
  }

  struct Iterator {
    using iterator_category = std::input_iterator_tag;

    Iterator(std::vector<size_t> editMask) : editMask(editMask) {}

    bool operator==(const Iterator &other) const {
      return editMask == other.editMask;
    }

    bool operator!=(const Iterator &other) const {
      return editMask != other.editMask;
    }

  private:
    std::vector<size_t> editMask;
  };

  void add(std::unique_ptr<ExprMutator> mutator) {
    auto numMutationsBefore = size();

    // TODO ensure that we haven't already added this mutator
    spdlog::info("adding mutator: {}", mutator->getName());

    // visit each node in the expression subtree via preorder traversal
    auto nodes = original->descendants();
    nodes.insert(nodes.begin(), original);
    size_t id = 0;
    for (auto *node : nodes) {
      spdlog::debug("mutating expr node [{}]: {}", id, node->toString());
      auto &editsAtNode = nodeEdits[id];

      mutator->generate(node, editsAtNode);
      id++;
    }

    auto numMutationsAfter = size();
    auto numMutationsAdded = numMutationsAfter - numMutationsBefore;

    spdlog::info("added {} mutations for mutator: {}", numMutationsAdded, mutator->getName());
    mutators.push_back(std::move(mutator));
  }

private:
  Expr const *original;
  size_t maxEdits;
  size_t numNodes;
  std::vector<std::vector<std::unique_ptr<ExprEdit>>> nodeEdits;
  std::vector<std::unique_ptr<ExprMutator>> mutators;

  ExprMutations(
    Expr const *original,
    size_t maxEdits
  ) : original(original),
      maxEdits(maxEdits),
      numNodes(original->size()),
      nodeEdits(original->size()),
      mutators()
  {
    assert (original != nullptr);
    assert (maxEdits >= 1);
  }

  void filter(
    std::function<bool(Expr const *)> predicate,
    size_t limit,
    size_t nodeIndex,
    size_t editsUsed,
    std::vector<size_t> &editMask,
    std::vector<std::unique_ptr<Expr>> &results
  ) {
    if (results.size() == limit) {
      return;
    }

    // test this expression
    if (nodeIndex >= numNodes || editsUsed == maxEdits) {
      auto expr = generateExpr(editMask);
      if (predicate(expr.get())) {
        results.push_back(std::move(expr));
      }
      return;
    }

    // no edit at this node
    filter(predicate, limit, nodeIndex + 1, editsUsed, editMask, results);

    // perform an edit at this node
    for (size_t editIndex = 1; editIndex < nodeEdits[nodeIndex].size(); editIndex++) {
      editMask[nodeIndex] = editIndex;
      filter(predicate, limit, nodeIndex + 1, editsUsed + 1, editMask, results);
    }
  }

  // transforms an edit mask into a mutated expression
  std::unique_ptr<Expr> generateExpr(std::vector<size_t> const &editMask) {
    assert (editMask.size() == numNodes);
    assert (nodeEdits.size() == numNodes);
    auto expr = original->copy();

    // destructively apply specified edit at each location
    std::vector<Expr*> nodes = expr->descendants(true);
    for (int i = numNodes - 1; i >= 0; i--) {
      auto node = nodes[i];
      auto editIndex = editMask[i];
      auto &editsAtNode = nodeEdits[i];
      // spdlog::debug("applying edit {} of {} at node {}", editIndex, i, editsAtNode.size());
      auto *edit = editsAtNode[editIndex].get();
      edit->apply(node);
    }

    return expr;
  }
};

}
