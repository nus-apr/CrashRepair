#include <crashrepairfix/Expr/Parser.h>

#include <spdlog/spdlog.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>
#include <tao/pegtl/contrib/parse_tree_to_dot.hpp>

using namespace tao::pegtl;

// https://github.com/taocpp/PEGTL/blob/3.x/doc/Getting-Started.md
// https://github.com/taocpp/PEGTL/blob/main/src/example/pegtl/parse_tree.cpp
// https://github.com/taocpp/PEGTL/blob/main/include/tao/pegtl/contrib/parse_tree.hpp

namespace crashrepairfix {

struct integer : plus<digit> {};
// TODO what's legal?
struct variable : identifier {};

struct plus : pad<one<'+'>, space> {};
struct minus : pad<one<'-'>, space> {};
struct multiply : pad<one<'*'>, space> {};
struct divide : pad<one<'/'>, space> {};

struct open_bracket : seq<one<'('>, star<space>> {};
struct close_bracket : seq<star<space>, one<')'>> {};

struct expression;
struct bracketed : seq<open_bracket, expression, close_bracket> {};
struct value : sor<integer, variable, bracketed>{};
struct product : list<value, sor<multiply, divide>> {};
struct expression : list<product, sor<plus, minus>> {};

struct grammar : seq<expression, eof> {};

// after a node is stored successfully, you can add an optional transformer like this:
struct rearrange
  : parse_tree::apply<rearrange>  // allows bulk selection, see selector<...>
{
  // recursively rearrange nodes. the basic principle is:
  //
  // from:          PROD/EXPR
  //                /   |   \          (LHS... may be one or more children, followed by OP,)
  //             LHS... OP   RHS       (which is one operator, and RHS, which is a single child)
  //
  // to:               OP
  //                  /  \             (OP now has two children, the original PROD/EXPR and RHS)
  //         PROD/EXPR    RHS          (Note that PROD/EXPR has two fewer children now)
  //             |
  //            LHS...
  //
  // if only one child is left for LHS..., replace the PROD/EXPR with the child directly.
  // otherwise, perform the above transformation, then apply it recursively until LHS...
  // becomes a single child, which then replaces the parent node and the recursion ends.
  template< typename Node, typename... States >
  static void transform( std::unique_ptr< Node >& n, States&&... st )
  {
    if (n->children.size() == 1) {
      n = std::move(n->children.back());
    } else {
      n->remove_content();
      auto& c = n->children;
      auto r = std::move(c.back());
      c.pop_back();
      auto o = std::move(c.back());
      c.pop_back();
      o->children.emplace_back(std::move(n));
      o->children.emplace_back(std::move(r));
      n = std::move(o);
      transform(n->children.front(), st...);
    }
  }
};

// select which rules in the grammar will produce parse tree nodes:
template<typename Rule>
using selector = parse_tree::selector<
  Rule,
  parse_tree::store_content::on<
    integer,
    variable
  >,
  parse_tree::remove_content::on<
    plus,
    minus,
    multiply,
    divide
  >,
  rearrange::on<
    product,
    expression
  >
>;

struct node : parse_tree::basic_node<node> {};

std::unique_ptr<Expr> convertParseNode(tao::pegtl::parse_tree::node *node);

std::unique_ptr<Expr> convertBinOpNode(BinOp::Opcode opcode, tao::pegtl::parse_tree::node *node) {
  return BinOp::create(
    convertParseNode(node->children[0].get()),
    convertParseNode(node->children[1].get()),
    opcode
  );
}

std::unique_ptr<Expr> convertIntNode(tao::pegtl::parse_tree::node *node) {
  auto value = std::stol(node->string());
  return IntConst::create(value);
}

std::unique_ptr<Expr> convertVarNode(tao::pegtl::parse_tree::node *node) {
  auto name = node->string();
  spdlog::warn("FIXME: assuming integer variable {}", name);
  auto resultType = ResultType::Int;
  return Var::create(name, resultType);
}

std::unique_ptr<Expr> convertParseNode(tao::pegtl::parse_tree::node *node) {
  auto nodeType = node->type;
  spdlog::debug("converting node with type: {}", nodeType);

  if (nodeType == "crashrepairfix::plus") {
    return convertBinOpNode(BinOp::Opcode::ADD, node);
  } else if (nodeType == "crashrepairfix::minus") {
    return convertBinOpNode(BinOp::Opcode::SUBTRACT, node);
  } else if (nodeType == "crashrepairfix::multiply") {
    return convertBinOpNode(BinOp::Opcode::MULTIPLY, node);
  } else if (nodeType == "crashrepairfix::divide") {
    return convertBinOpNode(BinOp::Opcode::DIVIDE, node);
  } else if (nodeType == "crashrepairfix::variable") {
    return convertVarNode(node);
  } else if (nodeType == "crashrepairfix::integer") {
    return convertIntNode(node);
  } else {
    spdlog::error("failed to convert parse node [{}]: {}", node->type, node->source);
    abort();
  }
}

std::unique_ptr<Expr> convertParseTree(tao::pegtl::parse_tree::node *root) {
  assert (root != nullptr && root->is_root());
  return convertParseNode(root->children[0].get());
}

std::unique_ptr<Expr> parse(std::string const &code) {
  memory_input input(code, "");
  if (const auto root = parse_tree::parse<grammar, selector>(input)) {
    return convertParseTree(root.get());
  }

  llvm::errs() << "FATAL ERROR: unable to parse constraint string: " << code << "\n";
  abort();
}

}