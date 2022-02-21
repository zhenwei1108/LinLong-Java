package com.github.zhenwei.sdk.builder.params;

import com.github.zhenwei.core.asn1.*;
import com.github.zhenwei.sdk.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;

/**
 * @author: zhangzhenwei
 * @description: CodingType
 * @since: 1.0.0
 * @date: 2022/2/21 10:21 下午
 */
public enum CodingType {
    DERPRINTABLESTRING,
    DEROCTETSTRING,
    DERBITSTRING,
    DERUTF8STRING,
    DERUNIVERSALSTRING,
    DERGRAPHICSTRING,
    DERVISIBLESTRING

    ;


    /**
     * @param [codingType, value]
     * @return com.github.zhenwei.core.asn1.ASN1Primitive
     * @author zhangzhenwei
     * @description encode 根据不同类型进行编码
     * @since: 1.0.0
     * @date 2022/2/21 10:48 下午
     */
    public static ASN1Primitive encode(CodingType codingType, byte[] value) throws WeGooCryptoException {
        ASN1Primitive oidValue = null;
        try {
            switch (codingType) {
                case DERBITSTRING: oidValue = DERBitString.fromByteArray(value);break;
                case DERUTF8STRING: oidValue = DERUTF8String.fromByteArray(value);break;
                case DEROCTETSTRING: oidValue = DEROctetString.fromByteArray(value);break;
                case DERGRAPHICSTRING: oidValue = DERGraphicString.fromByteArray(value);break;
                case DERVISIBLESTRING: oidValue = DERVisibleString.fromByteArray(value);break;
                case DERPRINTABLESTRING: oidValue = DERPrintableString.fromByteArray(value);break;
                //DERUniversalString:
                default: oidValue = DERUniversalString.fromByteArray(value);break;
            }
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.encode_err, e);
        }
        return oidValue;
    }

}
