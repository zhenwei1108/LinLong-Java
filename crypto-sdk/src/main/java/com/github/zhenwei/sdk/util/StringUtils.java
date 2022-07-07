package com.github.zhenwei.sdk.util;

public class StringUtils {

    public static boolean isEmpty(String data) {
        if (data == null) return true;
        return data.length() == 0;
    }


    public static boolean notEmpty(String data) {
        return !isEmpty(data);
    }

}
