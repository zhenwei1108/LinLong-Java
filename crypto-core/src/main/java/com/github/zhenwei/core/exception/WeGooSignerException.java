package com.github.zhenwei.core.exception;

import com.github.zhenwei.core.enums.exception.IExceptionEnum;

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