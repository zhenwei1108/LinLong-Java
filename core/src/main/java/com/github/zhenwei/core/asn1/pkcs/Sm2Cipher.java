package com.github.zhenwei.core.asn1.pkcs;

import com.github.zhenwei.core.asn1.*;
import com.github.zhenwei.core.crypto.engines.SM2Engine;

/**
 * @description: Sm2Cipher
 * 参考 GMT-0009
 * SM2Cipher ::= SEQENCE(
 * XCoordinate       Integer,  --x
 * YCoordinate       Integer,  --y
 * HASH              OCTET STRING SIZE(32), --杂凑
 * CipherText        OCTET STRING --密文
 * @author: zhangzhenwei
 * @since: 1.0.0
 * @date: 2022/3/6  9:30 上午
 */
public class Sm2Cipher extends ASN1Object {
    private SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
    private ASN1Integer x;
    private ASN1Integer y;
    private ASN1OctetString hash;
    private ASN1OctetString cipher;


    public static Sm2Cipher getInstance(Object obj) {
        if (obj instanceof Sm2Cipher) {
            return (Sm2Cipher) obj;
        } else if (obj instanceof byte[]) {
            return new Sm2Cipher((byte[]) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }


    private Sm2Cipher(byte[] data) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(data);
        int size = sequence.size();
        if (size != 4) {
            throw new IllegalArgumentException("Sm2Cipher data too short");
        }
        this.x = (ASN1Integer) sequence.getObjectAt(0);
        this.y = (ASN1Integer) sequence.getObjectAt(1);
        this.hash = (ASN1OctetString) sequence.getObjectAt(2);
        this.cipher = (ASN1OctetString) sequence.getObjectAt(3);
    }

    public Sm2Cipher(byte[] xData, byte[] yData, byte[] hashData, byte[] cipherData) {
        this.x = ASN1Integer.getInstance(xData);
        this.y = ASN1Integer.getInstance(yData);
        this.hash = ASN1OctetString.getInstance(hashData);
        this.cipher = ASN1OctetString.getInstance(cipherData);
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(this.x);
        vector.add(this.y);
        if (mode == SM2Engine.Mode.C1C2C3) {
            vector.add(this.cipher);
            vector.add(this.hash);
        } else {
            vector.add(this.hash);
            vector.add(this.cipher);
        }
        return new DERSequence(vector);
    }


    public SM2Engine.Mode getMode() {
        return mode;
    }

    public void setMode(SM2Engine.Mode mode) {
        this.mode = mode;
    }

    public ASN1Integer getX() {
        return x;
    }

    public ASN1Integer getY() {
        return y;
    }

    public ASN1OctetString getHash() {
        return hash;
    }

    public ASN1OctetString getCipher() {
        return cipher;
    }
}
