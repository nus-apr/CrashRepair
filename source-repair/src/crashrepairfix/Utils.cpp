#include <crashrepairfix/Utils.h>

#include <iostream>
#include <sstream>
#include <string>
#include <queue>

namespace crashrepairfix {

// adapted from https://stackoverflow.com/a/27511119
std::vector<std::string> split(const std::string &s, char delim) {
  std::stringstream ss(s);
  std::string item;
  std::vector<std::string> elems;
  while (std::getline(ss, item, delim)) {
    elems.push_back(std::move(item));
  }
  return elems;
}

std::vector<std::string> getLines(std::string const &s) {
  std::vector<std::string> lines;
  std::stringstream ss(s);
  std::string line;    
  while (std::getline(ss, line)) {
    lines.push_back(std::move(line));
  }
  return lines;
}

std::string getSource(clang::Stmt const *stmt, clang::SourceManager const &sourceManager) {
  static clang::LangOptions languageOptions;
  auto range = clang::CharSourceRange::getTokenRange(stmt->getSourceRange());
  return clang::Lexer::getSourceText(
    range, 
    sourceManager, 
    languageOptions
  ).str();
}

std::string getSource(clang::Stmt const *stmt, clang::ASTContext const &context) {
  return getSource(stmt, context.getSourceManager());
}

std::string yesOrNo(bool status) {
  if (status) {
    return "yes";
  } else {
    return "no";
  }
}

clang::SourceRange getRangeWithTokenEnd(clang::Stmt const *stmt, clang::ASTContext const &context) {
  return getRangeWithTokenEnd(stmt, context.getSourceManager());
}

clang::SourceRange getRangeWithTokenEnd(clang::Stmt const *stmt, clang::SourceManager const &sourceManager) {
  return getRangeWithTokenEnd(stmt->getSourceRange(), sourceManager);
}

clang::SourceRange getRangeWithTokenEnd(clang::SourceRange const &range, clang::SourceManager const &sourceManager) {
  static const clang::LangOptions languageOptions;
  auto expandedEnd = clang::Lexer::getLocForEndOfToken(range.getEnd(), 0, sourceManager, languageOptions);
  return clang::SourceRange(range.getBegin(), expandedEnd);
}

bool isInsideLoop(clang::DynTypedNode const &node, clang::ASTContext &context) {
  for (auto const parent : context.getParents(node)) {
    std::string nodeKind = parent.getNodeKind().asStringRef().str();
    if (nodeKind == "WhileStmt" || nodeKind == "ForStmt") { 
      return true;
    }
    if (isInsideLoop(parent, context)) {
      return true;
    }
  }
  return false;
}

bool isInsideLoop(clang::Stmt const *stmt, clang::ASTContext &context) {
  auto node = clang::DynTypedNode::create(*stmt);
  return isInsideLoop(node, context);
}

clang::FunctionDecl const * getParentFunctionDecl(clang::Stmt const *stmt, clang::ASTContext &context) {
  auto node = clang::DynTypedNode::create(*stmt);
  return getParentFunctionDecl(node, context);
}

clang::FunctionDecl const * getParentFunctionDecl(clang::DynTypedNode node, clang::ASTContext &context) {
  std::queue<clang::DynTypedNode> q;
  for (auto parent : context.getParents(node)) {
    q.push(parent);
  }

  while (!q.empty()) {
    node = q.front();
    if (auto functionDecl = node.get<clang::FunctionDecl>()) {
      return functionDecl;
    }
    for (auto parent : context.getParents(node)) {
      q.push(parent);
    }
    q.pop();
  }

  return nullptr;
}

}
