package com.github.zhenwei.sdk.builder.padding;

import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.sdk.util.PaddingUtil;
import lombok.var;

public abstract class AbstractPkcs5Padding {

    public static byte[] encoding(byte[] data, int blockingSize) {
        var padding = PaddingUtil.getPaddingLen(data, blockingSize);
        return Arrays.concatenate(data, padding);
    }

    public static byte[] decodePadding(byte[] data) {
        var padLen = data[data.length - 1];
        var result = new byte[data.length - padLen];
        System.arraycopy(data, 0, result, 0, result.length);
        return result;
    }
}
