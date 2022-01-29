package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public class WeGooCryptoException extends BaseWeGooException {

  public WeGooCryptoException() {
  }

  public WeGooCryptoException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum);
  }

  public WeGooCryptoException(IExceptionEnum iExceptionEnum,
      Throwable cause) {
    super(iExceptionEnum, cause);
  }

  public WeGooCryptoException(Throwable cause) {
    super(cause);
  }

  public WeGooCryptoException(String message) {
    super(message);
  }

}