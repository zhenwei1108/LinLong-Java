package com.github.zhenwei.pkix.operator;

public class OperatorCreationException
    extends OperatorException {

  public OperatorCreationException(String msg, Throwable cause) {
    super(msg, cause);
  }

  public OperatorCreationException(String msg) {
    super(msg);
  }
}