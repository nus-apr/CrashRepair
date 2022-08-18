#pragma once

#include <set>
#include <variant>

#include <clang/AST/Expr.h>
#include <clang/AST/LexicallyOrderedRecursiveASTVisitor.h>

#include <llvm/ADT/APInt.h>

#include <spdlog/spdlog.h>

#include "SourceLocation.h"

namespace crashrepairfix {

class ConstantFinder
  : public clang::LexicallyOrderedRecursiveASTVisitor<ConstantFinder> {
public:
  static std::vector<std::variant<llvm::APInt, llvm::APFloat>> find(
    clang::ASTContext const &context,
    clang::TranslationUnitDecl const *translationUnit,
    std::string const &restrictToFile
  ) {
    ConstantFinder finder(context, restrictToFile);
    finder.TraverseDecl(const_cast<clang::TranslationUnitDecl*>(translationUnit));
    return finder.result;
  }

  static std::vector<llvm::APInt> findIntegers(
    clang::ASTContext const &context,
    clang::TranslationUnitDecl const *translationUnit,
    std::string const &restrictToFile
  ) {
    std::vector<llvm::APInt> results;
    auto constants = find(context, translationUnit, restrictToFile);
    for (auto &constant : constants) {
      if (std::holds_alternative<llvm::APInt>(constant)) {
        results.push_back(std::get<llvm::APInt>(constant));
      }
    }
    return results;
  }

  static std::vector<llvm::APFloat> findReals(
    clang::ASTContext const &context,
    clang::TranslationUnitDecl const *translationUnit,
    std::string const &restrictToFile
  ) {
    std::vector<llvm::APFloat> results;
    auto constants = find(context, translationUnit, restrictToFile);
    for (auto &constant : constants) {
      if (std::holds_alternative<llvm::APFloat>(constant)) {
        results.push_back(std::get<llvm::APFloat>(constant));
      }
    }
    return results;
  }

  clang::ASTContext const &context;
  std::string restrictToFile;
  clang::SourceManager &sourceManager;
  std::unordered_map<std::string, std::string> relativeToAbsoluteFilenames;
  std::vector<std::variant<llvm::APInt, llvm::APFloat>> result;

  explicit ConstantFinder(clang::ASTContext const &context, std::string const &restrictToFile)
    : LexicallyOrderedRecursiveASTVisitor(context.getSourceManager()),
      restrictToFile(restrictToFile),
      context(context),
      sourceManager(const_cast<clang::SourceManager&>(context.getSourceManager())),
      relativeToAbsoluteFilenames(),
      result()
    {}

  std::string getStmtFilename(clang::Stmt const *stmt) {
    auto filename = sourceManager.getFilename(stmt->getBeginLoc()).str();
    if (relativeToAbsoluteFilenames.find(filename) == relativeToAbsoluteFilenames.end()) {
      relativeToAbsoluteFilenames[filename] = makeAbsolutePath(filename, sourceManager);
    }
    return relativeToAbsoluteFilenames[filename];
  }

  bool VisitIntegerLiteral(clang::IntegerLiteral *literal) {
    auto literalLoc = literal->getBeginLoc();
    if (!literalLoc.isValid()) {
      return true;
    }

    std::string inFile = getStmtFilename(literal);
    if (inFile != restrictToFile) {
      return true;
    }

    result.push_back(literal->getValue());
    return true;
  }

  bool VisitFloatingLiteral(clang::FloatingLiteral *literal) {
    auto literalLoc = literal->getBeginLoc();
    if (!literalLoc.isValid()) {
      return true;
    }

    std::string inFile = getStmtFilename(literal);
    if (inFile != restrictToFile) {
      return true;
    }

    result.push_back(literal->getValue());
    return true;
  }
};

}
