#pragma once

#include <memory>
#include <queue>
#include <string>
#include <unordered_set>
#include <vector>

#include <spdlog/spdlog.h>

namespace crashrepairfix {

class Var;

// FIXME add proper support for Boolean
enum class ResultType {
  Int,
  Float,
  Pointer,
};

class Expr {
public:
  // FIXME add proper support for True and False consts
  enum class Kind {
    BinOp,
    UnaryOp,
    FloatConst,
    IntConst,
    NullConst,
    Var,
    Result
  };

  Expr(const Expr&) = delete;
  Expr(Expr&&) = delete;
  Expr& operator=(const Expr&) = delete;
  Expr& operator=(Expr&&) = delete;

  virtual ~Expr() = default;

  /** Returns the set of vars that are used within this expression. */
  std::unordered_set<Var const *> vars() const {
    std::unordered_set<Var const *> result;
    for (auto const node : descendants(true)) {
      if (node->getExprKind() == Kind::Var) {
        result.insert((Var const *) node);
      }
    }
    return result;
  }

  /** Returns the size of this expression subtree. */
  size_t size() const {
    size_t size = 1;
    for (auto const &child : children) {
      size += child->size();
    }
    return size;
  }

  std::vector<Expr const *> descendants(bool includeRoot = false) const {
    std::vector<Expr const *> result;
    if (includeRoot) {
      result.push_back(this);
    }

    std::queue<Expr const *> queue;
    for (auto const &child : children) {
      queue.push(child.get());
    }

    while (!queue.empty()) {
      auto node = queue.front();
      result.push_back(node);
      queue.pop();
      for (auto const &child : node->children) {
        queue.push(child.get());
      }
    }

    return result;
  }

  std::vector<Expr*> descendants(bool includeRoot = false) {
    std::vector<Expr*> result;
    if (includeRoot) {
      result.push_back(this);
    }

    std::queue<Expr*> queue;
    for (auto &child : children) {
      queue.push(child.get());
    }

    while (!queue.empty()) {
      auto node = queue.front();
      result.push_back(node);
      queue.pop();
      for (auto &child : node->children) {
        queue.push(child.get());
      }
    }

    return result;
  }

  /** Determines whether this expression contains a result reference */
  bool refersToResult() const {
    for (auto descendant : descendants()) {
      if (descendant->getExprKind() == Kind::Result) {
        return true;
      }
    }
    return false;
  }

  /** Returns a deep copy of this expression. */
  virtual std::unique_ptr<Expr> copy() const = 0;

  /** Returns the kind of this expression */
  virtual Kind getExprKind() const = 0;

  /** Returns the type of the result produced by this expression */
  virtual ResultType getResultType() const = 0;

  /** Transforms this expression into C/C++ source code */
  virtual std::string toSource() const {
    return toString();
  }

  /** Writes this expression to a parsable string */
  virtual std::string toString() const = 0;

  static ResultType resultTypeFromString(std::string const &string) {
    if (string == "int") {
      return ResultType::Int;
    } else if (string == "float") {
      return ResultType::Float;
    } else if (string == "pointer") {
      return ResultType::Pointer;
    } else {
      spdlog::error("unrecognized result type: {}", string);
      abort();
    }
  }

  /** Returns a string-based description of a given result type. */
  static std::string resultTypeToString(ResultType const &type) {
    switch (type) {
      case ResultType::Int:
        return "int";
      case ResultType::Float:
        return "float";
      case ResultType::Pointer:
        return "pointer";
      default:
        abort();
    }
  }

  static std::string exprKindToString(Kind const &kind) {
    switch (kind) {
      case Kind::BinOp:
        return "BinOp";
      case Kind::UnaryOp:
        return "UnaryOp";
      case Kind::FloatConst:
        return "FloatConst";
      case Kind::IntConst:
        return "IntConst";
      case Kind::NullConst:
        return "NullConst";
      case Kind::Var:
        return "Var";
      case Kind::Result:
        return "Result";
      default:
        spdlog::error("cannot convert Expr::Kind to string: unrecognized kind");
        abort();
    }
  }

  /** Returns the name of the type produced by this expression. */
  std::string getResultTypeString() const {
    return resultTypeToString(getResultType());
  }

protected:
  Expr() : children() {}
  Expr(std::vector<std::unique_ptr<Expr>> children) : children(std::move(children)) {}

  std::vector<std::unique_ptr<Expr>> children;
};

}
