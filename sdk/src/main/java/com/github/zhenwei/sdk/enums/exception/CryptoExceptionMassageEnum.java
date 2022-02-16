package com.github.zhenwei.sdk.enums.exception;

public enum CryptoExceptionMassageEnum implements IExceptionEnum{
  params_err("params error", "参数错误"),
  params_short_err("params is too short", "参数太短"),

  ;

  private String message;

  private String desc;

  CryptoExceptionMassageEnum(String message, String desc) {
    this.message = message;
    this.desc = desc;
  }

  @Override
  public String getMessage() {
    return null;
  }

  @Override
  public String getDesc() {
    return null;
  }

}