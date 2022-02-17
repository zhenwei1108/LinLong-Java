package com.github.zhenwei.sdk.enums.exception;

public enum CryptoExceptionMassageEnum implements IExceptionEnum {
  params_short_err("params is too short", "参数太短"),
  parse_crl_err("parse crl error", "解析CRL失败"),
  build_err("build error", "构造失败"),

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