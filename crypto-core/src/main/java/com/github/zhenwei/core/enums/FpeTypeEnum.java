package com.github.zhenwei.core.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * @author: zhangzhenwei
 * @description: FpeTypeEnum
 *  FPE 处理的数据类型
 * @date: 2022/10/17  22:35
 * @since: 1.0
 */
@AllArgsConstructor
@Getter
public enum FpeTypeEnum {

  FPE_TYPE_IDCARD_WITH_BIRTHDAY(1, "身份证,保留格式(出生年月正确)"),
  FPE_TYPE_IDCARD_WITHOUT_BIRTHDAY(2, "身份证,不保留格式(出生年月不正确)"),
  FPE_TYPE_MOBILE_PHONE(3, "手机号码(加密后前两位不变)"),
  FPE_TYPE_CHINESE_NAME(4, "中文姓名(第一个字符不变)"),
  FPE_TYPE_DIGIT(5, "数字"),
  FPE_TYPE_ALPHABET(6, "字母"),
  FPE_TYPE_CHINESE_CHAR(7, "汉字"),
  FPE_TYPE_MIXING_CHAR(8, "混合型(包含数字,字母,汉字,标点等,其中加密后标点不变,其他都加密)"),

  ;

  private int type;
  private String desc;


}
