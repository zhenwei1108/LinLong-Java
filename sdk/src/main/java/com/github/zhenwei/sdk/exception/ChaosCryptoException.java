package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public class ChaosCryptoException extends BaseChaosException{

  public ChaosCryptoException() {
  }

  public ChaosCryptoException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum);
  }

  public ChaosCryptoException(IExceptionEnum iExceptionEnum,
      Throwable cause) {
    super(iExceptionEnum, cause);
  }

  public ChaosCryptoException(Throwable cause) {
    super(cause);
  }

  public ChaosCryptoException(String message) {
    super(message);
  }

}