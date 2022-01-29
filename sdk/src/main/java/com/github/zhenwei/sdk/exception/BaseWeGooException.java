package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public abstract class BaseWeGooException extends Exception{

  String message;
  String desc;

  public BaseWeGooException() {
  }

  public BaseWeGooException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum.getMessage());
    this.message = iExceptionEnum.getMessage();
    this.desc = iExceptionEnum.getDesc();
  }

  public BaseWeGooException(IExceptionEnum iExceptionEnum, Throwable cause) {
    super(iExceptionEnum.getMessage(), cause);
    this.message = cause.getMessage();
    this.desc = iExceptionEnum.getDesc();
  }

  public BaseWeGooException(Throwable cause) {
    super(cause);
    this.message = cause.getMessage();
  }

  public BaseWeGooException(String message) {
    super(message);
    this.message = message;
  }




}