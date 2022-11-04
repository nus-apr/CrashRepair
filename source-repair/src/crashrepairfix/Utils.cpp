#include <crashrepairfix/Utils.h>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <queue>
#include <vector>

#include <spdlog/spdlog.h>

#include <clang/AST/LexicallyOrderedRecursiveASTVisitor.h>
#include <clang/Basic/FileManager.h>

namespace crashrepairfix {


// Taken from https://clang.llvm.org/doxygen/Transforms_8cpp_source.html
clang::SourceLocation findSemiAfterLocation(
  clang::SourceLocation loc,
  clang::ASTContext &Ctx
) {
  clang::SourceManager &SM = Ctx.getSourceManager();
  if (loc.isMacroID()) {
    spdlog::error("failed to get semi-colon after location: location is a macro");
    if (!clang::Lexer::isAtEndOfMacroExpansion(loc, SM, Ctx.getLangOpts(), &loc)) {
      return clang::SourceLocation();
    }
  }
  // loc = clang::Lexer::getLocForEndOfToken(loc, /*Offset=*/0, SM, Ctx.getLangOpts());

  // Break down the source location.
  std::pair<clang::FileID, unsigned> locInfo = SM.getDecomposedLoc(loc);

  // Try to load the file buffer.
  bool invalidTemp = false;
  llvm::StringRef file = SM.getBufferData(locInfo.first, &invalidTemp);
  if (invalidTemp) {
    spdlog::error("failed to get semi-colon after location: could not load file buffer");
    return clang::SourceLocation();
  }

  const char *tokenBegin = file.data() + locInfo.second;

  // lex from the start of the given location
  clang::Lexer lexer(SM.getLocForStartOfFile(locInfo.first),
              Ctx.getLangOpts(),
              file.begin(), tokenBegin, file.end());
  clang::Token token;
  lexer.LexFromRawLexer(token);
  if (token.isNot(clang::tok::semi)) {
    spdlog::error(
      "failed to get semi-colon after location: next token is not a semi-colon [{}]",
      token.getName()
    );
    return clang::SourceLocation();
  }

  return token.getLocation();
}

// https://stackoverflow.com/questions/2417588/escaping-a-c-string
std::string escape_character(char c) {
  std::stringstream stream;
  stream << std::hex << static_cast<unsigned int>(static_cast<unsigned char>(c));
  std::string code = stream.str();
  return fmt::format("\\x{}{}", (code.size() < 2 ? "0" : ""), code);
}

void remove_trailing_newline(std::string &str) {
  if (str.back() == '\n') {
    str.erase(str.size() - 1);
  }
  if (str.back() == '\r') {
    str.erase(str.size() - 1);
  }
}

// adapted from https://stackoverflow.com/questions/83439/remove-spaces-from-stdstring-in-c
void strip_whitespace(std::string &str) {
  auto end_pos = std::remove(str.begin(), str.end(), ' ');
  str.erase(end_pos, str.end());
}

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

std::string cleanPath(llvm::StringRef path) {
  llvm::SmallString<256> result = path;
  llvm::sys::path::remove_dots(result, true);
  return std::string(result.str());
}

std::string cleanPath(std::string const &path) {
  return cleanPath(llvm::StringRef(path));
}

std::string makeAbsolutePath(std::string const &path, clang::SourceManager const &sourceManager) {
  llvm::SmallString<128> absPath(path);
  auto &fileManager = sourceManager.getFileManager();

  if (auto error_code = fileManager.getVirtualFileSystem().makeAbsolute(absPath)) {
    spdlog::error("failed to compute absolute path: {}", error_code.message());
    abort();
  }

  // resolve symlinks
  if (auto directory = fileManager.getDirectory(llvm::sys::path::parent_path(absPath.str()))) {
    auto directoryName = fileManager.getCanonicalName(*directory);
    // FIXME: getCanonicalName might fail to get real path on VFS.
    if (llvm::sys::path::is_absolute(directoryName)) {
      llvm::SmallString<128> absFilename;
      llvm::sys::path::append(
        absFilename,
        directoryName,
        llvm::sys::path::filename(absPath.str())
      );
      return cleanPath(absFilename.str());
    }
  }
  // https://llvm.org/doxygen/Path_8cpp_source.html#l00715
  // https://clang.llvm.org/extra/doxygen/namespaceclang_1_1tidy_1_1utils.html#affb1552884f0494c2f6ed0d9160ccb04
  return cleanPath(absPath.str());
}

clang::SourceRange getRangeWithTokenEnd(clang::Stmt const *stmt, clang::ASTContext const &context) {
  return getRangeWithTokenEnd(stmt->getSourceRange(), context);
}

// clang::SourceRange getRangeWithTokenEnd(clang::Stmt const *stmt, clang::SourceManager const &sourceManager) {
//   return getRangeWithTokenEnd(stmt->getSourceRange(), sourceManager);
// }

clang::SourceRange getRangeWithTokenEnd(
  clang::SourceRange const &range,
  clang::ASTContext const &context
) {
  static const clang::LangOptions languageOptions;

  auto const &sourceManager = context.getSourceManager();
  auto expandedEnd = clang::Lexer::getLocForEndOfToken(range.getEnd(), 0, sourceManager, languageOptions);

  // TODO write function to getRangeWithSemiColon
  // find the trailing semi-colon token, if any
  // https://lists.llvm.org/pipermail/cfe-dev/2014-July/038339.html
  // https://clang.llvm.org/doxygen/namespaceclang_1_1arcmt_1_1trans.html
  // auto semiLocation = findSemiAfterLocation(expandedEnd, const_cast<clang::ASTContext&>(context));
  // if (semiLocation.isValid()) {
  //   expandedEnd = semiLocation;
  // }

  // auto semiColonTokenStart = expandedEnd.getLocWithOffset(1);
  // auto semiColonTokenLength = clang::Lexer::MeasureTokenLength(
  //   semiColonTokenStart,
  //   sourceManager,
  //   languageOptions
  // );
  // auto semiColonTokenEnd = expandedEnd.getLocWithOffset(semiColonTokenLength);
  // auto semiColonCharRange = clang::CharSourceRange::getTokenRange(
  //   clang::SourceRange(semiColonTokenStart, semiColonTokenEnd)
  // );
  // auto semiColonText = clang::Lexer::getSourceText(
  //   semiColonCharRange,
  //   sourceManager,
  //   languageOptions
  // ).str();
  // spdlog::debug("TODO: check token contents: {}", semiColonText);

  return clang::SourceRange(range.getBegin(), expandedEnd);
}

bool isTopLevelStmt(clang::DynTypedNode const &node, clang::ASTContext &context) {
  for (auto const parent : context.getParents(node)) {
    std::string nodeKind = parent.getNodeKind().asStringRef().str();
    if (  nodeKind == "WhileStmt"
       || nodeKind == "ForStmt"
       || nodeKind == "CompoundStmt"
    ) {
      return true;
    }
  }
  return false;
}

bool isTopLevelStmt(clang::Stmt const *stmt, clang::ASTContext &context) {
  auto node = clang::DynTypedNode::create(*stmt);
  return isTopLevelStmt(node, context);
}

bool containsVarDecl(clang::Stmt const *stmt, clang::ASTContext const &context) {
  class Visitor : public clang::LexicallyOrderedRecursiveASTVisitor<Visitor> {
  public:
    bool foundVarDecl = false;

    explicit Visitor(clang::ASTContext const &context)
      : LexicallyOrderedRecursiveASTVisitor(context.getSourceManager())
      {}

    bool VisitVarDecl(clang::VarDecl *decl) {
      foundVarDecl = true;
      return false;
    }
  };

  Visitor visitor(context);
  visitor.TraverseStmt(const_cast<clang::Stmt*>(stmt));
  return visitor.foundVarDecl;
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

clang::TranslationUnitDecl const * getParentTranslationUnitDecl(clang::Decl const *decl, clang::ASTContext &context) {
  auto node = clang::DynTypedNode::create(*decl);
  return getParentTranslationUnitDecl(node, context);
}

clang::TranslationUnitDecl const * getParentTranslationUnitDecl(clang::DynTypedNode node, clang::ASTContext &context) {
  std::queue<clang::DynTypedNode> q;
  for (auto parent : context.getParents(node)) {
    q.push(parent);
  }

  while (!q.empty()) {
    node = q.front();
    if (auto translationUnitDecl = node.get<clang::TranslationUnitDecl>()) {
      return translationUnitDecl;
    }
    for (auto parent : context.getParents(node)) {
      q.push(parent);
    }
    q.pop();
  }

  return nullptr;
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

std::string convertAPIntToString(llvm::APInt const &integer) {
  std::string output;
  llvm::raw_string_ostream stream(output);
  integer.print(stream, true);
  return output;
}

std::string convertAPFloatToString(llvm::APFloat const &floating) {
  std::string output;
  llvm::raw_string_ostream stream(output);
  floating.print(stream);
  return output;
}

std::set<clang::VarDecl const *> findReachingVars(clang::Stmt const *stmt, clang::ASTContext &context) {
  auto node = clang::DynTypedNode::create(*stmt);
  return findReachingVars(node, context);
}

std::set<clang::VarDecl const *> findReachingVars(clang::DynTypedNode node, clang::ASTContext &context) {
  // FIXME everything in scope here BEFORE a given location
  std::set<clang::VarDecl const *> result;
  auto *function = getParentFunctionDecl(node, context);
  for (auto *decl : function->decls()) {
    if (auto varDecl = clang::dyn_cast<clang::VarDecl>(decl)) {
      result.insert(varDecl);
    }
  }
  return result;
}

}
