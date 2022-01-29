package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public class WeGooEnvelopException extends BaseWeGooException {

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