package com.github.zhenwei.core.enums;

import com.github.zhenwei.core.crypto.fpe.AlphabetType;
import com.github.zhenwei.core.crypto.fpe.ChineseType;
import com.github.zhenwei.core.crypto.fpe.FpeType;
import com.github.zhenwei.core.crypto.fpe.IntegerType;
import com.github.zhenwei.core.crypto.fpe.MixType;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum FpeTypeEnum {

  FPE_TYPE_IDCARD_WITH_BIRTHDAY(1, new IntegerType(), "身份证,保留格式(出生年月正确)"),
  FPE_TYPE_IDCARD_WITHOUT_BIRTHDAY(2, new IntegerType(), "身份证,不保留格式(出生年月不正确)"),
  FPE_TYPE_MOBILE_PHONE(3, new IntegerType(), "手机号码(加密后前两位不变)"),
  FPE_TYPE_CHINESE_NAME(4, new ChineseType(), "中文姓名(第一个字符不变)"),
  FPE_TYPE_DIGIT(5, new IntegerType(), "数字"),
  FPE_TYPE_ALPHABET(6, new AlphabetType(), "字母"),
  FPE_TYPE_CHINESE_CHAR(7, new ChineseType(), "汉字"),
  FPE_TYPE_MIXING_CHAR(8, new MixType(), "混合型(包含数字,字母,汉字,标点等,其中加密后标点不变,其他都加密)"),

  ;

  private int type;
  private FpeType fpeType;
  private String desc;


}
