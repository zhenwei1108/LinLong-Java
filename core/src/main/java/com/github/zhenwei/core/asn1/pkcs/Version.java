package com.github.zhenwei.core.asn1.pkcs;

import com.github.zhenwei.core.asn1.ASN1Integer;

import java.math.BigInteger;

/**
 * @description: Version
 *  版本信息
 * @author: zhangzhenwei
 * @since:1.0.0
 * @date: 2022/3/9  10:45 下午
 */
public class Version extends ASN1Integer {

    public Version(long value) {
        super(value);
    }

    public Version(BigInteger value) {
        super(value);
    }

    public Version(byte[] bytes) {
        super(bytes);
    }
}
