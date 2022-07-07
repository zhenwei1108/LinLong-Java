package com.github.zhenwei.core.util.encoders;

import com.github.zhenwei.core.util.Strings;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Utility class for converting Base64 data to bytes and back again.
 */
public class Base64 {

  private static final Encoder encoder = new Base64Encoder();

  public static String toBase64String(
      byte[] data) {
    return toBase64String(data, 0, data.length);
  }

  public static String toBase64String(
      byte[] data,
      int off,
      int length) {
    byte[] encoded = encode(data, off, length);
    return Strings.fromByteArray(encoded);
  }

  /**
   * encode the input data producing a base 64 encoded byte array.
   *
   * @return a byte array containing the base 64 encoded data.
   */
  public static byte[] encode(
      byte[] data) {
    return encode(data, 0, data.length);
  }

  /**
   * encode the input data producing a base 64 encoded byte array.
   *
   * @return a byte array containing the base 64 encoded data.
   */
  public static byte[] encode(
      byte[] data,
      int off,
      int length) {
    int len = encoder.getEncodedLength(length);
    ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

    try {
      encoder.encode(data, off, length, bOut);
    } catch (Exception e) {
      throw new EncoderException("exception encoding base64 string: " + e.getMessage(), e);
    }

    return bOut.toByteArray();
  }

  /**
   * Encode the byte data to base 64 writing it to the given output stream.
   *
   * @return the number of bytes produced.
   */
  public static int encode(
      byte[] data,
      OutputStream out)
      throws IOException {
    return encoder.encode(data, 0, data.length, out);
  }

  /**
   * Encode the byte data to base 64 writing it to the given output stream.
   *
   * @return the number of bytes produced.
   */
  public static int encode(
      byte[] data,
      int off,
      int length,
      OutputStream out)
      throws IOException {
    return encoder.encode(data, off, length, out);
  }

  /**
   * decode the base 64 encoded input data. It is assumed the input data is valid.
   *
   * @return a byte array representing the decoded data.
   */
  public static byte[] decode(
      byte[] data) {
    int len = data.length / 4 * 3;
    ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

    try {
      encoder.decode(data, 0, data.length, bOut);
    } catch (Exception e) {
      throw new DecoderException("unable to decode base64 data: " + e.getMessage(), e);
    }

    return bOut.toByteArray();
  }

  /**
   * decode the base 64 encoded String data - whitespace will be ignored.
   *
   * @return a byte array representing the decoded data.
   */
  public static byte[] decode(
      String data) {
    int len = data.length() / 4 * 3;
    ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

    try {
      encoder.decode(data, bOut);
    } catch (Exception e) {
      throw new DecoderException("unable to decode base64 string: " + e.getMessage(), e);
    }

    return bOut.toByteArray();
  }

  /**
   * decode the base 64 encoded String data writing it to the given output stream, whitespace
   * characters will be ignored.
   *
   * @return the number of bytes produced.
   */
  public static int decode(
      String data,
      OutputStream out)
      throws IOException {
    return encoder.decode(data, out);
  }

  /**
   * Decode to an output stream;
   *
   * @param base64Data The source data.
   * @param start      Start position.
   * @param length     the length.
   * @param out        The output stream to write to.
   */
  public static int decode(byte[] base64Data, int start, int length, OutputStream out) {
    try {
      return encoder.decode(base64Data, start, length, out);
    } catch (Exception e) {
      throw new DecoderException("unable to decode base64 data: " + e.getMessage(), e);
    }

  }

  /**
   * @param [data]
   * @return boolean
   * @author zhangzhenwei
   * @description
   * Base64 包含 大小写字母, 数字, 反斜杠, 加号.  使用 等号 进行补位. 长度为 4的倍数
   *      a~z = 97~122
   *      A~Z = 65~90
   *      '=' = 61
   *      0~9 = 48~57
   *      / = 47
   *      + = 43
   * @date 2022/1/28 09:14
   */
  public static boolean isBase64(String data) {
    //长度为4的倍数
    if (data.length() % 4 != 0) {
      return false;
    }
    byte[] bytes = data.getBytes(StandardCharsets.UTF_8);

    for (byte aByte : bytes) {
      if (!(aByte == 61 ||aByte == 43 || aByte == 47 || (aByte >= 48 && aByte <= 57) || (aByte >= 65
          && aByte <= 90) || (aByte >= 97 && aByte <= 122))) {
        return false;
      }
    }
    return true;
  }
}