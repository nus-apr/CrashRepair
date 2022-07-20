#include <crashrepairfix/Expr/Parser.h>

#include <spdlog/spdlog.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>
#include <tao/pegtl/contrib/parse_tree_to_dot.hpp>

using namespace tao::pegtl;

// https://github.com/taocpp/PEGTL/blob/3.x/doc/Getting-Started.md
// https://github.com/taocpp/PEGTL/blob/main/src/example/pegtl/parse_tree.cpp
// https://github.com/taocpp/PEGTL/blob/main/include/tao/pegtl/contrib/parse_tree.hpp

// https://en.cppreference.com/w/c/language/operator_precedence

namespace crashrepairfix {

struct comma : seq<star<space>, one<','>, star<space>> {};
struct open_bracket : seq<one<'('>, star<space>> {};
struct close_bracket : seq<star<space>, one<')'>> {};

struct type_int : string<'i', 'n', 't'> {};
struct type_float : string<'f', 'l', 'o', 'a', 't'> {};
struct type_pointer : string<'p', 'o', 'i', 'n', 't', 'e', 'r'> {};
struct type_name : sor<type_int, type_float, type_pointer> {};

struct relational_op : pad<sor<one<'<'>, string<'<', '='>, one<'>'>, string<'>', '='>, string<'=', '='>, string<'!', '='>>, space> {};
struct logical_op : pad<sor<string<'&', '&'>, string<'|', '|'>>, space> {};
struct arithmetic_op : pad<sor<one<'*'>, one<'/'>, one<'+'>, one<'-'>>, space> {};

// TODO what's legal?
struct var_name : identifier {};

struct integer : plus<digit> {};
struct variable : seq<string<'@', 'v', 'a', 'r'>, open_bracket, type_name, comma, var_name, close_bracket> {};
struct result : seq<string<'@', 'r', 'e', 's', 'u', 'l', 't'>, open_bracket, type_name, close_bracket> {};

struct plus : pad<one<'+'>, space> {};
struct minus : pad<one<'-'>, space> {};
struct multiply : pad<one<'*'>, space> {};
struct divide : pad<one<'/'>, space> {};

struct expression;
struct bracketed : seq<open_bracket, expression, close_bracket> {};
struct value : sor<integer, result, variable, bracketed>{};
struct product : list<value, sor<multiply, divide>> {};
struct expression : list<product, sor<plus, minus>> {};

struct grammar : seq<expression, eof> {};

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
    plus,
    minus,
    multiply,
    divide
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
  } else if (nodeType == "crashrepairfix::result") {
    return convertResultNode(node);
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
