package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public class ChaosEnvelopException extends BaseChaosException{

  public ChaosEnvelopException() {
  }

  public ChaosEnvelopException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum);
  }

  public ChaosEnvelopException(IExceptionEnum iExceptionEnum,
      Throwable cause) {
    super(iExceptionEnum, cause);
  }

  public ChaosEnvelopException(Throwable cause) {
    super(cause);
  }

  public ChaosEnvelopException(String message) {
    super(message);
  }

}