#include <crashrepairfix/Utils.h>

#include <iostream>
#include <sstream>
#include <string>
#include <queue>

#include <spdlog/spdlog.h>

#include <clang/Basic/FileManager.h>

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
