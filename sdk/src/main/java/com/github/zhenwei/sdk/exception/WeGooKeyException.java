package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public class WeGooKeyException extends BaseWeGooException {

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