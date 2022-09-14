package com.github.zhenwei.core.crypto.fpe;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author: zhangzhenwei
 * @description: IntegerType
 *  数字
 * @date: 2022/9/14  16:00
 * @since: 1.0.0
 */
public class IntegerType implements FpeType {

  final char[] data = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

  final ConcurrentHashMap<Character, Byte> charToByte = new ConcurrentHashMap<>(
      (int) (data.length * 1.25) + 1);
  final ConcurrentHashMap<Byte, Character> byteToChar = new ConcurrentHashMap<>(charToByte.size());

  public IntegerType() {
    init();
  }

  @Override
  public char[] available() {
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
