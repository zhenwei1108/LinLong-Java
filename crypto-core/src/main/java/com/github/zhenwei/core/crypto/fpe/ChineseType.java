package com.github.zhenwei.core.crypto.fpe;

import com.github.zhenwei.core.util.Pack;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * @author: zhangzhenwei
 * @description: ChineseType
 *  汉字
 * @date: 2022/9/14  18:15
 * @since: 1.0.0
 */
public class ChineseType implements FpeType{

  //Unicode编码的汉字表示范围是0x4E00-0x9FA5，所以其基数radix为20902，
  final Character[] data = new Character[20902];
  final HashMap<Character, Short> charToShort = new HashMap<Character, Short>(
      (int) (data.length * 1.25) + 1);
  final HashMap<Short, Character> shortToChar = new HashMap<Short, Character>(charToShort.size());

  /**
   * @author zhangzhenwei
   * @description 纯汉字格式数据，仅支持Unicode编码的基本汉字。如果输入的数据非Unicode格式，需要将格式转换为Unicode格式再做映射。
   * Unicode编码的汉字表示范围是0x4E00-0x9FA5，所以其基数radix为20902，
   * 需要将汉字‘一’（Unicode编码为0x4E00）映射为整数0，汉字‘丁’（Unicode编码为0x4E01）映射为整数1，以此类推，汉字‘龥’（Unicode编码为0x9FA5）映射为整数20901。
   * @date 2022/9/14  18:14
   * @since: 1.0.0
   */
  public ChineseType() {
    char begin = 0x4E00;
    for (char i = 0; i < data.length; i++) {
      data[i] = begin;
      begin++;
    }
    init();
  }

  @Override
  public Character[] available() {
    return data;
  }



  @Override
  public byte[] transform(char[] chars) {
    byte[] result = new byte[chars.length << 1];
    int index = 0;
    ByteBuffer allocate = ByteBuffer.allocate(2);
    for (int i = 0; i < chars.length; i++) {
      Short aShort = charToShort.get(chars[i]);
      byte[] array = allocate.putShort(aShort).array();
      System.arraycopy(array, 0, result, index, array.length);
      index += array.length;
      allocate.clear();
    }
    return result;
  }

  @Override
  public char[] transform(byte[] data) {
    char[] chars = new char[data.length / 2];
    for (int i = 1; i <= data.length; i++) {
      //奇数
      if ((i & 1) != 0) {
        byte[] bytes = new byte[2];
        System.arraycopy(data, i - 1, bytes, 0, 2);
        short i1 = Pack.bigEndianToShort(bytes, 0);
        Character character = shortToChar.get(i1);
        chars[i / 2] = character;
      }

    }
    return chars;
  }


  @Override
  public Map<Character, Byte> getCharToByte() {
    return null;
  }

  @Override
  public Map<Byte, Character> getByteToChar() {
    return null;
  }

  @Override
  public void init() {
    Character[] available = available();
    for (short i = 0; i < available.length; i++) {
      charToShort.put(available[i], i);
      shortToChar.put(i, available[i]);
    }
  }


}
