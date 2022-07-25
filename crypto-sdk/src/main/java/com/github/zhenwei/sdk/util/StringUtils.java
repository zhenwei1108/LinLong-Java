package com.github.zhenwei.sdk.util;

public class StringUtils {

    public static boolean isEmpty(String data) {
        return data == null || data.length() == 0;
    }

    public static boolean isBlank(String data) {
        return isEmpty(data) || data.trim().length() == 0;
    }


    public static boolean notEmpty(String data) {
        return !isEmpty(data);
    }

    public static boolean notBlank(String data) {
        return !isBlank(data);
    }

}
