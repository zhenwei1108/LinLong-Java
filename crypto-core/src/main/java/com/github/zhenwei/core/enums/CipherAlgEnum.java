package com.github.zhenwei.core.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum CipherAlgEnum implements BaseAlgEnum {
  SM2("SM2", ModeEnum.NONE),
  RSA("RSA/ECB/PKCS1Padding", ModeEnum.ECB),
  RSA_NONE_NOPADDING("RSA/ECB/PKCS1Padding", ModeEnum.ECB),
  SM4_ECB_PKCS7Padding("SM4/ECB/PKCS7Padding", ModeEnum.ECB),
  SM4_CBC_PKCS7Padding("SM4/CBC/PKCS7Padding", ModeEnum.CBC),


  ;

  private String alg;
  /**
   * 是否需要初始化向量
   */
  private ModeEnum modeEnum;
}