package com.github.zhenwei.core.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum FpeAlgEnum implements BaseAlgEnum {
  FPE_AES("AES"),
  FPE_SM4("SM4"),
  ;


  private String alg;

}
