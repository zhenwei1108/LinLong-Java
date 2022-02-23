package com.github.zhenwei.sdk.util;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;


public class ByteArrayUtil {

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

    public static boolean isBlank(byte[] data){
        return isEmpty(data) || new BigInteger(data).equals(BigInteger.ZERO);
    }


}
