package org.sdk.crypto.utils;

import java.util.Base64;

public class Base64Util {

  public static String encodeToString(byte[] data){
    return Base64.getEncoder().encodeToString(data);
  }

  public static byte[] decodeFromString(String data){
    return Base64.getDecoder().decode(data);
  }



}