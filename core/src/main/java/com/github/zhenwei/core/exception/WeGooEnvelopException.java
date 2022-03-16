package com.github.zhenwei.core.exception;

import com.github.zhenwei.core.enums.exception.IExceptionEnum;

public class WeGooEnvelopException extends WeGooCryptoException {

  public WeGooEnvelopException() {
  }

  public WeGooEnvelopException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum);
  }

  public WeGooEnvelopException(IExceptionEnum iExceptionEnum,
      Throwable cause) {
    super(iExceptionEnum, cause);
  }

  public WeGooEnvelopException(Throwable cause) {
    super(cause);
  }

  public WeGooEnvelopException(String message) {
    super(message);
  }

}