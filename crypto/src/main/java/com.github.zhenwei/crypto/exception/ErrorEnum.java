package org.sdk.crypto.exception;

public enum ErrorEnum implements IException{
  GEN_KEYPAIR_ERROR("生成密钥对失败", 9110001),
  GEN_SM2_KEYPAIR_ERROR("生成SM2密钥对失败",9110002),
  GEN_ED25519_KEYPAIR_ERROR("生成ED25519密钥对失败",9110003),

  /*
  对称算法  91101XX
   */
  GEN_KEY_ERROR("生成密钥失败", 9110101),


  /*
  签名验签  91102XX
   */
  SIGN_DATA_ERROR("数据签名失败",9110200),
  VERIFY_DATA_ERROR("数据验签失败",9110201),


   /*
  加解密  91103XX
   */
  RSA_ENC_DATA_ERROR("RSA加解密失败",9110300),


  ;

  private String message;
  private int code;


  ErrorEnum(String message, int code) {
    this.message = message;
    this.code = code;
  }

  @Override
  public String getMessage() {
    return this.message;
  }

  @Override
  public int getCode() {
    return this.code;
  }
}