package com.github.zhenwei.sdk.structure;

import com.github.zhenwei.core.asn1.pkcs.Sm2Signature;
import com.github.zhenwei.sdk.util.BytesUtil;

/**
 * @description: SignedDataBuilder
 *  签名值结构组装
 * @author: zhangzhenwei 
 * @since: 1.0.1
 * @date: 2022/6/3  10:12
 */
public class SignedDataBuilder {

    public static Sm2Signature formatSm2SignedData(byte[] rs) {
        return Sm2Signature.getInstance(rs);
    }

    public static Sm2Signature buildSm2SignedData(byte[] r, byte[] s){
        return new Sm2Signature(r, s);
    }

    public static byte[] formatSm2SignedData(Sm2Signature signature) {
        return BytesUtil.mergeBytes(signature.getR().getValue().toByteArray(), signature.getS().getValue().toByteArray());
    }


}
