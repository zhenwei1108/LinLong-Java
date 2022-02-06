package com.github.zhenwei.sdk.enums.exception;

public enum SignatureExceptionMessageEnum implements IExceptionEnum {
  sign_data_err("sign data error","签名失败"),
  verify_data_err("verify data error","验签失败"),

  ;

  private String message;

  private String desc;


  SignatureExceptionMessageEnum(String message, String desc) {
    this.message = message;
    this.desc = desc;
  }

  @Override
  public String getMessage() {
    return this.message;
  }

  @Override
  public String getDesc() {
    return this.desc;
  }
}