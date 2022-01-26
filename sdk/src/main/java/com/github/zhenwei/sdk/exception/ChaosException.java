package com.github.zhenwei.sdk.exception;

public class ChaosException extends Exception{

  private String msg;

  public ChaosException() {
  }

  public ChaosException(String message) {
    super(message);
    this.msg = message;
  }

  public ChaosException(String message, Throwable cause) {
    super(message, cause);
  }

  public ChaosException(Throwable cause) {
    super(cause);
  }

  public ChaosException(String message, Throwable cause, boolean enableSuppression,
      boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}