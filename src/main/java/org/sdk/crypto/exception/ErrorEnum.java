package org.sdk.crypto.exception;

public enum ErrorEnum implements IException{
  GEN_KEYPAIR_ERROR("生成密钥对失败", 9110001),
  GEN_SM2_KEYPAIR_ERROR("生成SM2密钥对失败",9110002),
  GEN_ED25519_KEYPAIR_ERROR("生成ED25519密钥对失败",9110003),




  /*
  对称算法
   */
  GEN_KEY_ERROR("生成密钥失败", 9110101),
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
