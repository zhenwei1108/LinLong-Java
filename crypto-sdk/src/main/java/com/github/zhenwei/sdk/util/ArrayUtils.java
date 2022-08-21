package com.github.zhenwei.sdk.util;

import com.github.zhenwei.core.util.encoders.Hex;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;


public class ArrayUtils {

  public static byte[] mergeBytes(byte[]... datas) {
    if (datas != null && datas.length > 0) {
      //计算总长度
      int totalLen = Arrays.stream(datas).mapToInt(data -> data.length).sum();

      byte[] result = new byte[totalLen];

      AtomicInteger limit = new AtomicInteger();
      //填充结果
      Arrays.stream(datas).forEach(data -> {
        int index = limit.getAndAdd(data.length);
        System.arraycopy(data, 0, result, index, data.length);
      });
      return result;
    }
    return new byte[0];
  }

  public static byte[] splitBytes(byte[] in, int inOff, int len) {
    byte[] result = new byte[len];
    System.arraycopy(in, inOff, result, 0, len);
    return result;
  }

  public static boolean isEmpty(byte[] data) {
    return data == null || data.length == 0;
  }

  public static boolean notEmpty(byte[] data) {
    return !isEmpty(data);
  }

  public static boolean isBlank(byte[] data) {
    return isEmpty(data) || new BigInteger(data).equals(BigInteger.ZERO);
  }

  public static String byteToHexString(byte[] data) {
    return Hex.toHexString(data);
  }

  public static byte[] hexStringToByte(String hexString) {
    return Hex.decode(hexString);
  }

  public static int byteToInt(byte[] data) {
    return ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.nativeOrder()).put(data).getInt();
  }

  public static byte[] intToByte(int data) {
    return ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.nativeOrder()).putInt(data).array();
  }

  public static long byteToLang(byte[] data) {
    return ByteBuffer.allocate(Long.BYTES).order(ByteOrder.nativeOrder()).put(data).getLong();
  }

  public static byte[] longToByte(long data) {
    return ByteBuffer.allocate(Long.BYTES).order(ByteOrder.nativeOrder()).putLong(data).array();
  }

  public static<T> boolean isEmpty(T[] data) {
    return data == null || data.length == 0;
  }

  public static<T> boolean notEmpty(T[] data) {
    return !isEmpty(data);
  }


}
