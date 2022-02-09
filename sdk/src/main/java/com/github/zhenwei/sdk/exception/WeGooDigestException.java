package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public class WeGooDigestException extends BaseWeGooException{

  public WeGooDigestException() {
  }

  public WeGooDigestException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum);
  }

  public WeGooDigestException(IExceptionEnum iExceptionEnum,
      Throwable cause) {
    super(iExceptionEnum, cause);
  }

  public WeGooDigestException(Throwable cause) {
    super(cause);
  }

  public WeGooDigestException(String message) {
    super(message);
  }
}