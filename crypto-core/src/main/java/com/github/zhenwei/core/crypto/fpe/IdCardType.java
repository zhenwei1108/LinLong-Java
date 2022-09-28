package com.github.zhenwei.core.crypto.fpe;

import java.text.SimpleDateFormat;
import java.util.Date;

public class IdCardType extends DigitType {

  private final String START_DATE = "19000101";
  private final int TIME_FOR_DAY = 60 * 1000 * 60 * 24;
  private boolean keepBirthday = false;

  public IdCardType() {
    super();
  }

  public IdCardType(boolean keepBirthday) {
    super();
    this.keepBirthday = keepBirthday;
  }

  /**
   * @author zhangzhenwei
   * @description 1. 剔除最后一位
   *              2. 将身份证的年月日，转换为 据 1900 年的天数（4-5位数字）。
   *              3. 拼接后按照数字进行运算
   * @date 2022/9/28  23:00
   * @since:
   */
  @Override
  public byte[] transform(char[] request) {
    //去除最后一位
    char[] excLash = new char[request.length - 1];
    System.arraycopy(request, 0, excLash, 0, excLash.length);

    if (keepBirthday) {
      try {
        char[] yyyyMMdd = new char[8];
        System.arraycopy(excLash, 6, yyyyMMdd, 0, yyyyMMdd.length);
        Date target = new SimpleDateFormat("yyyyMMdd").parse(new String(yyyyMMdd));
        Date start = new SimpleDateFormat("yyyyMMdd").parse(START_DATE);
        //天数
        char[] dayChars = String.valueOf((target.getTime() - start.getTime()) / TIME_FOR_DAY)
            .toCharArray();
        //结果
        char[] result = new char[14];
        result[6] = '0';
        result[7] = '0';
        result[8] = '0';
        result[9] = '0';
        result[10] = '0';
        System.arraycopy(excLash, 0, result, 0, 6);
        System.arraycopy(dayChars, 0, result, result.length - dayChars.length - 3, dayChars.length);
        System.arraycopy(excLash, 14, result, result.length - 3, 3);
        excLash = result;
      } catch (Exception e) {
        throw new IllegalArgumentException("data time in id card error");
      }
    }

    return super.transform(excLash);
  }

  @Override
  public char[] transform(byte[] data) {
    return super.transform(data);
  }
}
