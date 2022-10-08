package com.github.zhenwei.core.crypto.fpe;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author: zhangzhenwei
 * @description: IdCardType
 *  保留日期格式，将年月日换算成5位数字（用天表示，从1900年开始），加密后将中间5位还原成年月日，再计算最后一位。
 * @date: 2022/9/29  16:11
 * @since: 1.0
 */
public class IdCardType extends DigitType {
  private final int[] SEED = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
  private final char[] RESULT = {'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'};
  //起始时间(1900年1月1日)，用于计算目标时间的天数差值。
  private final long START_DATE = -2209017600000L;

  private final int TIME_FOR_DAY = 60 * 1000 * 60 * 24;
  private boolean keepBirthday = false;

  public IdCardType() {
    super();
  }

  public IdCardType(boolean keepBirthday) {
    this();
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
        //天数
        char[] dayChars = String.valueOf((target.getTime() - START_DATE) / TIME_FOR_DAY)
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
      //身份证 18位
      byte[] result = new byte[18];
      //中间5位数字，用于转换年月日
      byte[] dayChars = new byte[5];
      System.arraycopy(data, 0, result, 0, 6);
      System.arraycopy(data, 6, dayChars, 0, dayChars.length);
      //拷贝最后三位
      System.arraycopy(data, data.length - 3, result, result.length - 4, 3);
      //将中间5位数字还原成年月日
      long days = Long.parseLong(new String(super.transform(dayChars)));
      Date date = new Date(START_DATE + days * TIME_FOR_DAY);

      char[] yyyyMMdd = new SimpleDateFormat("yyyyMMdd").format(date).toCharArray();
      System.arraycopy(super.transform(yyyyMMdd), 0, result, 6, yyyyMMdd.length);
      char[] transform = super.transform(result);
      transform[transform.length - 1] = getLastNum(result);
      return transform;
  }

  /**
   * @author zhangzhenwei
   * @description 计算身份证最后一位
   * @return 最后一位
   * @date 2022/10/8  22:28
   * @since: 1.0
   */
  private char getLastNum(byte[] data) {
    int total = 0;
    //由前17位计算最后一位。
    for (int i = 0; i < 17; i++) {
      total += (data[i] * SEED[i]);
    }
    return RESULT[total % 11];
  }

}
