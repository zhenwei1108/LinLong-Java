package com.github.zhenwei.core.crypto.fpe;

import java.util.HashMap;
import java.util.Map;

/**
 * @author: zhangzhenwei
 * @description: IntegerType
 *  数字
 * @date: 2022/9/14  16:00
 * @since: 1.0.0
 */
public class IntegerType implements FpeType {

  final Character[] data = new Character[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

  final HashMap<Character, Byte> charToByte = new HashMap<>((int) (data.length * 1.25) + 1);
  final HashMap<Byte, Character> byteToChar = new HashMap<>(charToByte.size());

  public IntegerType() {
    init();
  }

  @Override
  public Character[] available() {
    return data;
  }

  @Override
  public Map<Character, Byte> getCharToByte() {
    return charToByte;
  }

  @Override
  public Map<Byte, Character> getByteToChar() {
    return byteToChar;
  }
}
