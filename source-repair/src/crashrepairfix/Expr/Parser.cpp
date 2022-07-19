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

void convert(tao::pegtl::parse_tree::node &root) {
  spdlog::debug("is root? {}", root.is_root());
  spdlog::debug("real root type: {}", root.children[0]->type);

  // what type of node are we dealing with?
}

std::unique_ptr<Expr> parse(std::string const &code) {
  memory_input input(code, "");
  if (const auto root = parse_tree::parse<grammar, selector>(input)) {
    // convert(*root);
    return IntConst::create(99);
  }

  llvm::errs() << "FATAL ERROR: unable to parse constraint string: " << code << "\n";
  abort();
}

}
