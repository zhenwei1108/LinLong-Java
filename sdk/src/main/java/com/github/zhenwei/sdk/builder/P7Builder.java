package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.pkcs.ContentInfo;
import com.github.zhenwei.sdk.enums.Pkcs7ContentInfoTypeEnum;

/**
 * @description: P7Builder
 * pkcs 7 构造者， 包含： 签名，信封
 * 参考 RFC-2315(p7) RFC-3852(CMS)
 * @author: zhangzhenwei
 * @since: 1.0.0
 * @date: 2022/2/28  10:32 下午
 */
public class P7Builder {

    public void getInstance(Object obj) {
    }


    /**
     * @param [typeEnum, data]
     * @return com.github.zhenwei.core.asn1.pkcs.ContentInfo
     * @author zhangzhenwei
     * @description 封装pkcs7
     *  ContentInfo ::= SEQUENCE {
     *      contentType ContentType,
     *      content
     *        [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
     * @date 2022/3/1  7:27 下午
     * @since: 1.0.0
     */
    public ContentInfo build(Pkcs7ContentInfoTypeEnum typeEnum, byte[] data) {
        ASN1Encodable asn1Encodable = null;
        switch (typeEnum) {
            case DATA:
                asn1Encodable = genData(data);
                break;
            case SIGNED_DATA:
            case DIGESTED_DATA:
            case ENCRYPTED_DATA:
            case ENVELOPED_DATA:
            case SIGNED_AND_ENVELOPED_DATA:
        }

        return new ContentInfo(typeEnum.getOid(), asn1Encodable);
    }


    private DEROctetString genData(byte[] data) {
        return new DEROctetString(data);
    }


}
