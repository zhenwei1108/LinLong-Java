package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public class WeGooCipherException extends WeGooCryptoException {

  public WeGooCipherException() {
  }

  public WeGooCipherException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum);
  }

  public WeGooCipherException(IExceptionEnum iExceptionEnum,
      Throwable cause) {
    super(iExceptionEnum, cause);
  }

  public WeGooCipherException(Throwable cause) {
    super(cause);
  }

  public WeGooCipherException(String message) {
    super(message);
  }

}