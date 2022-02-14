package com.github.zhenwei.sdk.enums.exception;

public enum CipherExceptionMessageEnum implements IExceptionEnum {
  cipher_data_err("cipher data error","秘密处理失败"),
  encrypt_data_err("encrypt data error","加密失败"),
  decrypt_data_err("decrypt data error","解密失败"),
  iv_param_empty_err("iv param empty error","初始化向量 iv 为空"),
  ;

  private String message;
  private String desc;

  @Override
  public String getMessage() {
    return null;
  }

  @Override
  public String getDesc() {
    return null;
  }

  CipherExceptionMessageEnum(String message, String desc) {
    this.message = message;
    this.desc = desc;
  }
}