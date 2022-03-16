package com.github.zhenwei.core.exception;

import com.github.zhenwei.core.enums.exception.IExceptionEnum;

public class WeGooDigestException extends WeGooCryptoException{

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