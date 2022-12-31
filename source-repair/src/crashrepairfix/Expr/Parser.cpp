#include <crashrepairfix/Expr/Parser.h>

#include <climits>

#include <spdlog/spdlog.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/analyze.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>
#include <tao/pegtl/contrib/parse_tree_to_dot.hpp>
#include <tao/pegtl/contrib/trace.hpp>

using namespace tao::pegtl;

// https://github.com/taocpp/PEGTL/blob/3.x/doc/Getting-Started.md
// https://github.com/taocpp/PEGTL/blob/main/src/example/pegtl/parse_tree.cpp
// https://github.com/taocpp/PEGTL/blob/main/include/tao/pegtl/contrib/parse_tree.hpp

// https://en.cppreference.com/w/c/language/operator_precedence

namespace crashrepairfix {

struct dot : one<'.'> {};
struct plusplus : string<'+', '+'> {};
struct arrow : string<'-', '>'> {};
struct comma : seq<star<space>, one<','>, star<space>> {};
struct open_square_bracket : one<'['> {};
struct closed_square_bracket : one<']'> {};
struct open_bracket : seq<one<'('>, star<space>> {};
struct close_bracket : seq<star<space>, one<')'>> {};

struct type_int : string<'i', 'n', 't', 'e', 'g', 'e', 'r'> {};
struct type_float : string<'f', 'l', 'o', 'a', 't'> {};
struct type_pointer : string<'p', 'o', 'i', 'n', 't', 'e', 'r'> {};
struct type_name : sor<type_int, type_float, type_pointer> {};

struct var_name : seq<
  sor<identifier_first, plusplus>,
  star<sor<identifier_other, digit, dot, arrow, plusplus, open_square_bracket, closed_square_bracket>>
> {};
struct integer : plus<digit> {};
struct variable : seq<string<'@', 'v', 'a', 'r'>, open_bracket, type_name, comma, var_name, close_bracket> {};
struct result : seq<string<'@', 'r', 'e', 's', 'u', 'l', 't'>, open_bracket, type_name, close_bracket> {};

struct null : string<'N', 'U', 'L', 'L'> {};
struct int_max : string<'I', 'N', 'T', '_', 'M', 'A', 'X'> {};
struct int_min : string<'I', 'N', 'T', '_', 'M', 'I', 'N'> {};
struct long_max : string<'L', 'O', 'N', 'G', '_', 'M', 'A', 'X'> {};
struct long_min : string<'L', 'O', 'N', 'G', '_', 'M', 'I', 'N'> {};
struct constant : sor<null, int_max, int_min, long_max, long_min> {};

struct left_shift : pad<string<'<', '<'>, space> {};
struct right_shift : pad<string<'>', '>'>, space> {};
struct less_than : pad<one<'<'>, space> {};
struct lesser_or_equal : pad<string<'<', '='>, space> {};
struct greater_than : pad<one<'>'>, space> {};
struct greater_or_equal : pad<string<'>', '='>, space> {};
struct equals : pad<string<'=', '='>, space> {};
struct not_equals : pad<string<'!', '='>, space> {};
struct logical_and : pad<string<'&', '&'>, space> {};
struct logical_or : pad<string<'|', '|'>, space> {};
struct plus : pad<one<'+'>, space> {};
struct minus : pad<one<'-'>, space> {};
struct multiply : pad<one<'*'>, space> {};
struct divide : pad<one<'/'>, space> {};

struct expression;
struct bracketed : seq<open_bracket, expression, close_bracket> {};
struct value : sor<integer, result, variable, constant, bracketed> {};

struct product : list<value, sor<multiply, divide>> {}; // 3
struct sum : list<product, sor<plus, minus>> {}; // 4
struct shift : list<sum, sor<left_shift, right_shift>> {}; // 5
struct compare : list<shift, sor<lesser_or_equal, less_than, greater_or_equal, greater_than>> {}; // 6
struct equality : list<compare, sor<equals, not_equals>> {}; // 7
struct expression : list<equality, sor<logical_and, logical_or>> {}; // 11/12

struct grammar : seq<expression, eof> {};

struct rearrange : parse_tree::apply<rearrange> {
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
  static void transform(std::unique_ptr< Node >& n, States&&... st)
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

template<typename Rule>
using selector = parse_tree::selector<
  Rule,
  parse_tree::store_content::on<
    integer,
    variable,
    var_name,
    type_name
  >,
  parse_tree::remove_content::on<
    result,
    null,
    int_max,
    int_min,
    long_max,
    long_min,
    plus,
    minus,
    multiply,
    divide,
    equals,
    left_shift,
    right_shift,
    not_equals,
    logical_and,
    logical_or,
    less_than,
    lesser_or_equal,
    greater_than,
    greater_or_equal
  >,
  rearrange::on<
    product,
    sum,
    shift,
    compare,
    equality,
    expression
  >
>;

struct node : parse_tree::basic_node<node> {};

std::unique_ptr<Expr> convertParseNode(tao::pegtl::parse_tree::node *node);

ResultType convertTypeNode(tao::pegtl::parse_tree::node *node) {
  auto typeName = node->string();
  return Expr::resultTypeFromString(typeName);
}

std::unique_ptr<Expr> convertResultNode(tao::pegtl::parse_tree::node *node) {
  auto resultType = convertTypeNode(node->children[0].get());
  return Result::create(resultType);
}

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

std::string convertVarNameNode(tao::pegtl::parse_tree::node *node) {
  return node->string();
}

std::unique_ptr<Expr> convertVarNode(tao::pegtl::parse_tree::node *node) {
  auto resultType = convertTypeNode(node->children[0].get());
  auto name = convertVarNameNode(node->children[1].get());
  return Var::create(name, resultType);
}

std::unique_ptr<Expr> convertParseNode(tao::pegtl::parse_tree::node *node) {
  auto nodeType = node->type;
  spdlog::debug("converting node with type: {}", nodeType);

  // if (nodeType == "crashrepairfix::binary_op") {
  //   return convertBinOpNode(node);
  if (nodeType == "crashrepairfix::plus") {
    return convertBinOpNode(BinOp::Opcode::ADD, node);
  } else if (nodeType == "crashrepairfix::minus") {
    return convertBinOpNode(BinOp::Opcode::SUBTRACT, node);
  } else if (nodeType == "crashrepairfix::multiply") {
    return convertBinOpNode(BinOp::Opcode::MULTIPLY, node);
  } else if (nodeType == "crashrepairfix::divide") {
    return convertBinOpNode(BinOp::Opcode::DIVIDE, node);
  } else if (nodeType == "crashrepairfix::equals") {
    return convertBinOpNode(BinOp::Opcode::EQ, node);
  } else if (nodeType == "crashrepairfix::not_equals") {
    return convertBinOpNode(BinOp::Opcode::NEQ, node);
  } else if (nodeType == "crashrepairfix::greater_than") {
    return convertBinOpNode(BinOp::Opcode::GT, node);
  } else if (nodeType == "crashrepairfix::less_than") {
    return convertBinOpNode(BinOp::Opcode::LT, node);
  } else if (nodeType == "crashrepairfix::greater_or_equal") {
    return convertBinOpNode(BinOp::Opcode::GTE, node);
  } else if (nodeType == "crashrepairfix::lesser_or_equal") {
    return convertBinOpNode(BinOp::Opcode::LTE, node);
  } else if (nodeType == "crashrepairfix::logical_and") {
    return convertBinOpNode(BinOp::Opcode::AND, node);
  } else if (nodeType == "crashrepairfix::logical_or") {
    return convertBinOpNode(BinOp::Opcode::OR, node);
  } else if (nodeType == "crashrepairfix::left_shift") {
    return convertBinOpNode(BinOp::Opcode::LEFT_SHIFT, node);
  } else if (nodeType == "crashrepairfix::right_shift") {
    return convertBinOpNode(BinOp::Opcode::RIGHT_SHIFT, node);
  } else if (nodeType == "crashrepairfix::null") {
    return NullConst::create();
  } else if (nodeType == "crashrepairfix::int_max") {
    return IntConst::create(INT_MAX);
  } else if (nodeType == "crashrepairfix::int_min") {
    return IntConst::create(INT_MIN);
  } else if (nodeType == "crashrepairfix::long_max") {
    return IntConst::create(LONG_MAX);
  } else if (nodeType == "crashrepairfix::long_min") {
    return IntConst::create(LONG_MIN);
  } else if (nodeType == "crashrepairfix::variable") {
    return convertVarNode(node);
  } else if (nodeType == "crashrepairfix::integer") {
    return convertIntNode(node);
  } else if (nodeType == "crashrepairfix::result") {
    return convertResultNode(node);
  } else {
    spdlog::error("failed to convert parse node [{}]: {}", node->type, node->source);
    return std::unique_ptr<Expr>(nullptr);
  }
}

std::unique_ptr<Expr> convertParseTree(tao::pegtl::parse_tree::node *root) {
  assert (root != nullptr && root->is_root());
  return convertParseNode(root->children[0].get());
}

std::unique_ptr<Expr> parse(std::string const &code) {
  spdlog::info("parsing expression: {}", code);
  memory_input input(code, "");

  [[maybe_unused]] const std::size_t issues = tao::pegtl::analyze<grammar>();

  // TODO debugging
  // tao::pegtl::standard_trace<grammar>(input);

  if (const auto root = parse_tree::parse<grammar, selector>(input)) {
    spdlog::info("converting parse tree to expression...");
    return convertParseTree(root.get());
  }

  llvm::errs() << "WARNING: unable to parse constraint string: " << code << "\n";
  return std::unique_ptr<Expr>(nullptr);
}

}
