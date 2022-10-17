package com.github.zhenwei.core.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * @author: zhangzhenwei
 * @description: FpeAlgEnum
 *  Fpe 支持的算法列表
 * @date: 2022/10/17  22:34
 * @since: 1.0
 */
@AllArgsConstructor
@Getter
public enum FpeAlgEnum implements BaseAlgEnum {
  FPE_AES("AES"),
  FPE_SM4("SM4"),
  ;


  private String alg;

}
