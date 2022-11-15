package com.github.zhenwei.core.asn1.sm2;

import com.github.zhenwei.core.asn1.*;
import com.github.zhenwei.core.crypto.engines.SM2Engine;

import java.math.BigInteger;

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
        if (this.mode == SM2Engine.Mode.C1C2C3){
            this.cipher = (ASN1OctetString) sequence.getObjectAt(2);
            this.hash = (ASN1OctetString) sequence.getObjectAt(3);
        }

    }


    public Sm2Cipher(ASN1Integer x, ASN1Integer y, ASN1OctetString hash, ASN1OctetString cipher) {
        this.x = x;
        this.y = y;
        this.hash = hash;
        this.cipher = cipher;
    }

    public Sm2Cipher(byte[] xData, byte[] yData, byte[] hashData, byte[] cipherData) {
        this(ASN1Integer.getInstance(xData), ASN1Integer.getInstance(yData),
                new DEROctetString(hashData), new DEROctetString(cipherData));
    }

    public Sm2Cipher(BigInteger xData, BigInteger yData, byte[] hashData, byte[] cipherData) {
        this(new ASN1Integer(xData), new ASN1Integer(yData),  new DEROctetString(hashData),
                new DEROctetString(cipherData));
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

    public Sm2Cipher setMode(SM2Engine.Mode mode) {
        this.mode = mode;
        return this;
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
