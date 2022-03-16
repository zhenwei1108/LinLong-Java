package com.github.zhenwei.sdk.enums.exception;

public enum CryptoExceptionMassageEnum implements IExceptionEnum {
  params_short_err("params is too short", "参数太短"),
  parse_crl_err("parse crl error", "解析CRL失败"),
  parse_p10_err("parse p10 error", "解析P10失败"),
  build_err("build error", "构造失败"),
  encode_err("encode error", "编码失败"),
  generate_signed_data_err("generate signed data error", "构造Pkcs7 签名数据失败"),
  generate_jks_err("generate jks error", "构造 jks 失败"),

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