package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public class WeGooSignerException extends WeGooCryptoException{

  public WeGooSignerException() {
  }

  public WeGooSignerException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum);
  }

  public WeGooSignerException(IExceptionEnum iExceptionEnum,
      Throwable cause) {
    super(iExceptionEnum, cause);
  }

  public WeGooSignerException(Throwable cause) {
    super(cause);
  }

  public WeGooSignerException(String message) {
    super(message);
  }
}