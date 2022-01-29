package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public class ChaosKeyException extends BaseChaosException{

  public ChaosKeyException() {
  }

  public ChaosKeyException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum);
  }

  public ChaosKeyException(IExceptionEnum iExceptionEnum,
      Throwable cause) {
    super(iExceptionEnum, cause);
  }

  public ChaosKeyException(Throwable cause) {
    super(cause);
  }

  public ChaosKeyException(String message) {
    super(message);
  }

}