package com.github.zhenwei.core.enums.exception;

public enum DigestExceptionMessageEnum implements IExceptionEnum{
  digest_data_err("digest data error","计算摘要失败"),


  ;

  private String message;

  private String desc;

  DigestExceptionMessageEnum(String message, String desc) {
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