package com.github.zhenwei.core.crypto.fpe;

import com.github.zhenwei.core.crypto.params.FPEParameters;
import com.github.zhenwei.core.crypto.params.KeyParameter;
import java.util.Map;

public interface FpeType {

  default int radix() {
    return available().length;
  }

  Character[] available();

  default byte[] transform(char[] chars) {
    byte[] result = new byte[chars.length];
    for (int i = 0; i < chars.length; i++) {
      result[i] = getCharToByte().get(chars[i]);
    }
    return result;
  }

  default char[] transform(byte[] data) {
    char[] chars = new char[data.length];
    for (int i = 0; i < data.length; i++) {
      chars[i] = getByteToChar().get(data[i]);
    }
    return chars;
  }

  Map<Character, Byte> getCharToByte();

  Map<Byte, Character> getByteToChar();

  default void init() {
    Character[] available = available();
    for (Byte i = 0; i < available.length; i++) {
      getCharToByte().put(available[i], i);
      getByteToChar().put(i, available[i]);
    }
  }

  default byte[] cipher(FPEEngine fpeEngine, byte[] key, int radix, byte[] tweak, byte[] in,
      boolean isEncrypt) {
    fpeEngine.init(isEncrypt, new FPEParameters(new KeyParameter(key), radix, tweak));
    byte[] enc = new byte[in.length];
    fpeEngine.processBlock(in, 0, in.length, enc, 0);
    return enc;
  }

}
