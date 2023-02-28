#pragma once

#include "Expr.h"

namespace crashrepairfix {

class Const : public Expr {};

class NullConst : public Const {
public:
  Expr::Kind getExprKind() const override {
    return Expr::Kind::NullConst;
  }

  virtual ResultType getResultType() const override {
    return ResultType::Pointer;
  }

  virtual std::unique_ptr<Expr> copy() const override {
    return create();
  }

  static std::unique_ptr<NullConst> create() {
    return std::unique_ptr<NullConst>(new NullConst());
  }

  virtual std::string toString() const override {
    return "0";
  }

protected:
  NullConst() : Const() {}
};

class IntConst : public Const {
public:
  Expr::Kind getExprKind() const override {
    return Expr::Kind::IntConst;
  }

  virtual ResultType getResultType() const override {
    return ResultType::Int;
  }

  long getValue() const {
    return value;
  }

  virtual std::unique_ptr<Expr> copy() const override {
    return create(value);
  }

  static std::unique_ptr<IntConst> create(long value) {
    return std::unique_ptr<IntConst>(new IntConst(value));
  }

  virtual std::string toString() const override {
    return std::to_string(value);
  }

protected:
  IntConst(long value) : Const(), value(value) {}

private:
  long value;
};

class FloatConst : public Const {
public:
  Expr::Kind getExprKind() const override {
    return Expr::Kind::FloatConst;
  }

  virtual ResultType getResultType() const override {
    return ResultType::Float;
  }

  double getValue() const {
    return value;
  }

  virtual std::unique_ptr<Expr> copy() const override {
    return create(value);
  }

  static std::unique_ptr<FloatConst> create(double value) {
    return std::unique_ptr<FloatConst>(new FloatConst(value));
  }

  virtual std::string toString() const override {
    return std::to_string(value);
  }

protected:
  FloatConst(double value) : Const(), value(value) {}

private:
  double value;
};

}
