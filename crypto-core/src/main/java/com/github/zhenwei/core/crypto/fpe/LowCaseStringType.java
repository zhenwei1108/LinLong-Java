package com.github.zhenwei.core.crypto.fpe;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author: zhangzhenwei 
 * @description: LowCaseStringType
 *  小写字母
 * @date: 2022/9/14  15:51
 * @since: 1.0.0
 */
public class LowCaseStringType implements FpeType {

  final char[] data = new char[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
      'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};


  final ConcurrentHashMap<Character, Byte> charToByte = new ConcurrentHashMap<>(
      (int) (data.length * 1.25) + 1);
  final ConcurrentHashMap<Byte, Character> byteToChar = new ConcurrentHashMap<>(charToByte.size());

  public LowCaseStringType() {
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