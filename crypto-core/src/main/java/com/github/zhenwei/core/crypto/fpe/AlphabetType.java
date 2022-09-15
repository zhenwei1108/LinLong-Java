package com.github.zhenwei.core.crypto.fpe;

import java.util.HashMap;
import java.util.Map;


public class AlphabetType implements FpeType {

  Character[] data = new Character[]{
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
      'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
      't', 'u', 'v', 'w', 'x', 'y', 'z'};

  final HashMap<Character, Byte> charToByte = new HashMap<>(
      (int) (data.length * 1.25) + 1);
  final HashMap<Byte, Character> byteToChar = new HashMap<>(charToByte.size());

  public AlphabetType() {
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
