package com.github.zhenwei.sdk.util;

import com.github.zhenwei.core.util.encoders.Hex;

import java.nio.ByteBuffer;

/**
 * @author: zhangzhenwei
 * @description: MathUtil数学相关工具
 * @since: 1.0.0
 * @date: 2022/2/20 10:28 下午
 */
public class MathUtil {

    public static String byteToHexString(byte[] data){
        return Hex.toHexString(data);
    }

    public static byte[] hexStringToByte(String hexString){
        return Hex.decode(hexString);
    }

    public static int byteToInt(byte[] data){
        return ByteBuffer.allocate(Integer.BYTES).put(data).getInt();
    }

    public static byte[] intToByte(int data){
        return ByteBuffer.allocate(Integer.BYTES).putInt(data).array();
    }

    public static long byteToLang(byte[] data){
        return ByteBuffer.allocate(Long.BYTES).put(data).getLong();
    }

    public static byte[] longToByte(long data){
        return ByteBuffer.allocate(Long.BYTES).putLong(data).array();
    }


}
