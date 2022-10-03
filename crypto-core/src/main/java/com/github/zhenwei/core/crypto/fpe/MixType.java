package com.github.zhenwei.core.crypto.fpe;

import com.github.zhenwei.core.enums.FpeTypeEnum;
import com.github.zhenwei.core.util.Pack;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author: zhangzhenwei
 * @description: MixType
 *  混合
 * @date: 2022/9/14  22:15
 * @since: 1.0.0
 */
public class MixType implements FpeType {

  Character[] data;
  LinkedHashMap<MixEntity, Map<Integer, Character>> map = new LinkedHashMap<>();
  LinkedHashMap<Integer, Character> other = new LinkedHashMap<>();
  ConcurrentHashMap<Character, Short> charToByte;
  ConcurrentHashMap<Short, Character> byteToChar;

  public MixType() {

    init();
  }

  @Override
  public Character[] available() {
    return data;
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
  public byte[] transform(char[] in) {
    List<Character> characters = Arrays.asList(available());
    for (int i = 0; i < in.length; i++) {
      int index = characters.indexOf(in[i]);
      //-1 不在范围内，或为标点符号。
      if (index > -1) {
        for (Entry<MixEntity, Map<Integer, Character>> entry : map.entrySet()) {
          MixEntity key = entry.getKey();
          if (Arrays.asList(key.getFpeType().available()).contains(in[i])) {
            entry.getValue().put(i, in[i]);
            break;
          }
        }
      } else {
        //捕获标点符号。
        other.put(i, in[i]);
      }
    }

    byte[] result = new byte[0];
    for (Entry<MixEntity, Map<Integer, Character>> entry : map.entrySet()) {
      MixEntity key = entry.getKey();
      Map<Integer, Character> value = entry.getValue();
      Collection<Character> values = value.values();
      //将value转为数组
      Character[] chars = values.toArray(new Character[0]);
      char[] data = new char[chars.length];
      for (int i = 0; i < chars.length; i++) {
        data[i] = chars[i];
      }
      byte[] transform = key.getFpeType().transform(data);
      byte[] total = new byte[transform.length + result.length];
      System.arraycopy(result, 0, total, 0, result.length);
      System.arraycopy(transform, 0, total, result.length, transform.length);
      result = total;
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
        Character character = byteToChar.get(i1);
        chars[i / 2] = character;
      }

    }
    return chars;
  }

  @Override
  public void init() {
    DigitType digitType = new DigitType();
    MixEntity integersEntity = new MixEntity(FpeTypeEnum.FPE_TYPE_DIGIT, digitType);
    map.put(integersEntity, new LinkedHashMap<>());
    AlphabetType alphabetType = new AlphabetType();
    MixEntity alphabetsEntity = new MixEntity(FpeTypeEnum.FPE_TYPE_ALPHABET, alphabetType);
    map.put(alphabetsEntity, new LinkedHashMap<>());
    ChineseType chineseType = new ChineseType();
    MixEntity chinesesEntity = new MixEntity(FpeTypeEnum.FPE_TYPE_CHINESE_CHAR, chineseType);
    map.put(chinesesEntity, new LinkedHashMap<>());

    Character[] digitChars = digitType.available();
    Character[] alphabetChars = alphabetType.available();
    Character[] chineseChars = chineseType.available();

    data = new Character[digitChars.length + alphabetChars.length + chineseChars.length];
    System.arraycopy(digitChars, 0, data, 0, digitChars.length);
    System.arraycopy(alphabetChars, 0, data, digitChars.length, alphabetChars.length);
    System.arraycopy(chineseChars, 0, data, digitChars.length + alphabetChars.length,
        chineseChars.length);
    charToByte = new ConcurrentHashMap<>((int) (data.length * 1.25) + 1);
    byteToChar = new ConcurrentHashMap<>(charToByte.size());
    Character[] available = available();
    for (short i = 0; i < available.length; i++) {
      charToByte.put(available[i], i);
      byteToChar.put(i, available[i]);
    }
  }

  public LinkedHashMap<MixEntity, Map<Integer, Character>> getMap() {
    return map;
  }

  public LinkedHashMap<Integer, Character> getOther() {
    return other;
  }
}
