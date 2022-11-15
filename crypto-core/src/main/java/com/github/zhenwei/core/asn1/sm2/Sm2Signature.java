package com.github.zhenwei.core.asn1.sm2;

import com.github.zhenwei.core.asn1.*;

/**
 * @description: Sm2Signature
 * SM2签名结构。 GMT-0009
 * @author: zhangzhenwei
 * @since: 1.0.0
 * @date: 2022/3/3  9:59 下午
 */
public class Sm2Signature extends ASN1Object {

    private int dataLength = 32;

    private ASN1Integer r;

    private ASN1Integer s;

    public static Sm2Signature getInstance(Object obj) {
        if (obj instanceof Sm2Signature) {
            return (Sm2Signature) obj;
        } else if (obj instanceof byte[]) {
            return new Sm2Signature(ASN1Sequence.getInstance(obj));
        } else if (obj instanceof ASN1Sequence) {
            return new Sm2Signature((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    private Sm2Signature(ASN1Sequence sequence) {
        // r and s
        if (sequence.size() != 2) {
            throw new IllegalArgumentException("data is not validated");
        }
        this.r = (ASN1Integer) sequence.getObjectAt(0);
        this.s = (ASN1Integer) sequence.getObjectAt(1);
    }


    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(r);
        vector.add(s);
        return new DERSequence(vector);
    }


    public Sm2Signature(byte[] r, byte[] s) {
        if (r.length > dataLength || s.length > dataLength) {
            throw new IllegalArgumentException("data is too long more than 32 bytes");
        }
        this.r = ASN1Integer.getInstance(r);
        this.s = ASN1Integer.getInstance(s);
    }

    public ASN1Integer getR() {
        return r;
    }

    public ASN1Integer getS() {
        return s;
    }
}
