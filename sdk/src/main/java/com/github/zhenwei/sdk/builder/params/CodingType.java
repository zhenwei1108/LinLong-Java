package com.github.zhenwei.sdk.builder.params;

import com.github.zhenwei.core.asn1.*;
import com.github.zhenwei.sdk.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;

import java.nio.charset.StandardCharsets;

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
    DERVISIBLESTRING,

    ;

    /**
     * @param [codingType, value]
     * @return com.github.zhenwei.core.asn1.ASN1Primitive
     * @author zhangzhenwei
     * @description encode 根据不同类型进行编码
     * @since: 1.0.0
     * @date 2022/2/21 10:48 下午
     */
    public static <T> ASN1Primitive encode(CodingType codingType, byte[] value) throws WeGooCryptoException {
        ASN1Primitive oidValue = null;
        try {
            switch (codingType) {
                case DERBITSTRING: oidValue = new DERBitString(value);break;
                case DERUTF8STRING: oidValue = new DERUTF8String(new String(value, StandardCharsets.UTF_8));break;
                case DEROCTETSTRING: oidValue = new DEROctetString(value); break;
                case DERGRAPHICSTRING: oidValue = new DERGraphicString(value);break;
                case DERVISIBLESTRING: oidValue = new DERVisibleString(new String(value, StandardCharsets.UTF_8));break;
                case DERPRINTABLESTRING: oidValue = new DERPrintableString(new String(value, StandardCharsets.UTF_8));break;
                //DERUniversalString:
                default: oidValue = DERUniversalString.fromByteArray(value);break;
            }
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.encode_err, e);
        }
        return oidValue;
    }

}
