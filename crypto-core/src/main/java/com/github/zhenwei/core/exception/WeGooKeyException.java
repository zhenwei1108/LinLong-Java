package com.github.zhenwei.core.exception;

import com.github.zhenwei.core.enums.exception.IExceptionEnum;

public class WeGooKeyException extends WeGooCryptoException {

  public WeGooKeyException() {
  }

  public WeGooKeyException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum);
  }

  public WeGooKeyException(IExceptionEnum iExceptionEnum,
      Throwable cause) {
    super(iExceptionEnum, cause);
  }

  public WeGooKeyException(Throwable cause) {
    super(cause);
  }

  public WeGooKeyException(String message) {
    super(message);
  }

}