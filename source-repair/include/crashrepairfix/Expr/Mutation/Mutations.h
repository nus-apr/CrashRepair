#pragma once

#include <memory>
#include <vector>

#include <spdlog/spdlog.h>

#include "Mutators.h"

namespace crashrepairfix {

class ExprMutations {
public:
  static ExprMutations generate(
    Expr *original,
    size_t maxEdits = 1
  ) {
    auto mutations = ExprMutations(original, maxEdits);
    return mutations;
  }

  ExprMutations(ExprMutations &&other) noexcept :
    original(other.original),
    maxEdits(other.maxEdits),
    numNodes(other.numNodes),
    nodeEdits(std::move(other.nodeEdits)),
    mutators(std::move(other.mutators))
  {}

  ~ExprMutations(){}

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
    // TODO ensure that we haven't already added this mutator
    spdlog::info("adding mutator: {}", mutator->getName());

    // visit each node in the expression subtree via preorder traversal
    auto nodes = original->descendants();
    nodes.insert(nodes.begin(), original);
    size_t id = 0;
    for (auto *node : nodes) {
      spdlog::debug("mutating expr node [{}]", id);
      mutator->generate(node, nodeEdits[id]);
      id++;
    }

    spdlog::info("added mutations for mutator: {}", mutator->getName());
    mutators.push_back(std::move(mutator));
  }

private:
  Expr *original;
  size_t maxEdits;
  size_t numNodes;
  std::vector<std::vector<std::unique_ptr<ExprEdit>>> nodeEdits;
  std::vector<std::unique_ptr<ExprMutator>> mutators;

  ExprMutations(
    Expr *original,
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
};

}
