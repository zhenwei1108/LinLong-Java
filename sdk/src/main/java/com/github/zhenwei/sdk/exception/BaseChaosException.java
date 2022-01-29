package com.github.zhenwei.sdk.exception;

import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;

public abstract class BaseChaosException extends Exception{

  String message;
  String desc;

  public BaseChaosException() {
  }

  public BaseChaosException(IExceptionEnum iExceptionEnum) {
    super(iExceptionEnum.getMessage());
    this.message = iExceptionEnum.getMessage();
    this.desc = iExceptionEnum.getDesc();
  }

  public BaseChaosException(IExceptionEnum iExceptionEnum, Throwable cause) {
    super(iExceptionEnum.getMessage(), cause);
    this.message = cause.getMessage();
    this.desc = iExceptionEnum.getDesc();
  }

  public BaseChaosException(Throwable cause) {
    super(cause);
    this.message = cause.getMessage();
  }

  public BaseChaosException(String message) {
    super(message);
    this.message = message;
  }




}