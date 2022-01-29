package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public class ChaosCipherException extends BaseChaosException{

  public ChaosCipherException() {
  }

  public ChaosCipherException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum);
  }

  public ChaosCipherException(IExceptionEnum iExceptionEnum,
      Throwable cause) {
    super(iExceptionEnum, cause);
  }

  public ChaosCipherException(Throwable cause) {
    super(cause);
  }

  public ChaosCipherException(String message) {
    super(message);
  }

}