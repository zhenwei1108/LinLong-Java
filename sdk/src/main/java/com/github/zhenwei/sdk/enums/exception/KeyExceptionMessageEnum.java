package com.github.zhenwei.sdk.enums.exception;

/**
 * @description: 密钥相关异常信息
 * @author: zhangzhenwei
 * @date: 2022/1/28 22:53
 */
public enum KeyExceptionMessageEnum implements IExceptionEnum {
  generate_keypair_err("generate key pair error","生成密钥对失败"),
  generate_key_err("generate key error","生成密钥失败"),
  structure_public_key_err("structure public key error", "构造公钥失败"),
  ;


  private String message;

  private String desc;


  KeyExceptionMessageEnum(String message, String desc) {
    this.message = message;
    this.desc = desc;
  }

  @Override
  public String getMessage() {
    return message;
  }

  @Override
  public String getDesc() {
    return desc;
  }
}