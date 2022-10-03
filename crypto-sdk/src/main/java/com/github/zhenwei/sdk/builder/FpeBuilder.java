package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.crypto.engines.SM4Engine;
import com.github.zhenwei.core.crypto.fpe.ChineseType;
import com.github.zhenwei.core.crypto.fpe.DigitType;
import com.github.zhenwei.core.crypto.fpe.FPEEngine;
import com.github.zhenwei.core.crypto.fpe.FPEFF1Engine;
import com.github.zhenwei.core.crypto.fpe.FpeType;
import com.github.zhenwei.core.crypto.fpe.IdCardType;
import com.github.zhenwei.core.enums.FpeAlgEnum;
import com.github.zhenwei.core.enums.FpeTypeEnum;
import java.security.Key;

public class FpeBuilder {

//  public static void main(String[] args) throws BaseWeGooException {
//    FpeBuilder fpeBuilder = new FpeBuilder();
//    Key key = new KeyBuilder().buildKey(KeyEnum.AES_128);
//    String cipher = fpeBuilder.cipher(FpeAlgEnum.FPE_AES, FpeTypeEnum.FPE_TYPE_IDCARD_WITH_BIRTHDAY,
//        new byte[0], "456123199901011234", key);
//  }


  public String cipher(FpeAlgEnum fpeAlgEnum, FpeTypeEnum fpeTypeEnum, byte[] tweak, String data,
      Key key) {
    //aes,sm4
    FPEEngine fpeEngine =
        fpeAlgEnum == FpeAlgEnum.FPE_SM4 ? new FPEFF1Engine(new SM4Engine()) : new FPEFF1Engine();
    FpeType fpeType;
    char[] chars = data.toCharArray();
    char[] transform = new char[0];
    switch (fpeTypeEnum) {
      //数字
      case FPE_TYPE_DIGIT:
        //身份证,不保留格式(出生年月不正确)
      case FPE_TYPE_IDCARD_WITHOUT_BIRTHDAY:
        fpeType = new DigitType();
        byte[] plainText = fpeType.transform(chars);
        byte[] cipher = fpeType.cipher(fpeEngine, key.getEncoded(), fpeType.radix(), tweak,
            plainText, true);
        transform = fpeType.transform(cipher);
        break;
      //身份证,保留格式(出生年月正确), 最后一位计算得来
      case FPE_TYPE_IDCARD_WITH_BIRTHDAY:
        //最后一位不参与计算，  有可能为X。
        fpeType = new IdCardType(true);
        cipher = fpeType.cipher(fpeEngine, key.getEncoded(), fpeType.radix(), tweak,
            fpeType.transform(chars), true);
        //将日期还原
        transform = fpeType.transform(cipher);
        break;
      //汉字
      case FPE_TYPE_CHINESE_CHAR:
        fpeType = new ChineseType();
        plainText = fpeType.transform(chars);
        cipher = fpeType.cipher(fpeEngine, key.getEncoded(), fpeType.radix(), tweak,
            plainText, true);
        transform = fpeType.transform(cipher);
        break;
      //手机号码(加密后前两位不变)
      case FPE_TYPE_MOBILE_PHONE:
        fpeType = new DigitType();
        //前两位 不参与
        char[] realChars = new char[chars.length - 2];
        System.arraycopy(chars, 2, realChars, 0, realChars.length);
        plainText = fpeType.transform(chars);
        cipher = fpeType.cipher(fpeEngine, key.getEncoded(), fpeType.radix(), tweak,
            plainText, true);
        transform = fpeType.transform(cipher);
        //还原回来前两位
        System.arraycopy(transform, 0, chars, 2, transform.length);
        transform = chars;
        break;
      //中文姓名(第一个字符不变)
      case FPE_TYPE_CHINESE_NAME:
        fpeType = new ChineseType();
        cipher = fpeType.cipher(fpeEngine, key.getEncoded(), fpeType.radix(), tweak,
            fpeType.transform(chars), true);
        transform = fpeType.transform(cipher);
        break;
      //混合型(包含数字,字母,汉字,标点等,其中加密后标点不变,其他都加密)
      case FPE_TYPE_MIXING_CHAR:
        break;
      //字母
      case FPE_TYPE_ALPHABET:
        break;

      default:
        throw new IllegalStateException("Unexpected value: " + fpeTypeEnum);
    }

    return String.valueOf(transform);
  }


}
