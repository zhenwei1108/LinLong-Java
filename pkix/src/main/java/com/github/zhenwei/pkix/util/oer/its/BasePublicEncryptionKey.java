package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Choice;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERTaggedObject;

/**
 * BasePublicEncryptionKey ::= CHOICE {
 * eciesNistP256         EccP256CurvePoint,
 * eciesBrainpoolP256r1  EccP256CurvePoint,
 * ...
 * }
 */
public class BasePublicEncryptionKey
    extends ASN1Object
    implements ASN1Choice
{
    public static final int eciesNistP256 = 0;
    public static final int eciesBrainpoolP256r1 = 1;
    public static final int extension = 2;


    private final int choice;
    private final ASN1Encodable value;


    public BasePublicEncryptionKey(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
    }

    public static BasePublicEncryptionKey getInstance(Object objectAt)
    {
        if (objectAt instanceof BasePublicEncryptionKey)
        {
            return (BasePublicEncryptionKey)objectAt;
        }
        ASN1TaggedObject dto = ASN1TaggedObject.getInstance(objectAt);

        ASN1Encodable value;

        switch (dto.getTagNo())
        {
        case eciesNistP256:
        case eciesBrainpoolP256r1:
            value = EccP256CurvePoint.getInstance(dto.getObject());
            break;
        case extension:
            value = DEROctetString.getInstance(dto.getObject());
            break;
        default:
            throw new IllegalStateException("unknown choice " + dto.getTagNo());
        }

        return new BasePublicEncryptionKey(dto.getTagNo(), value);
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, value);
    }

    public static class Builder
    {

        private int choice;
        private ASN1Encodable value;

        public Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder setValue(EccCurvePoint value)
        {
            this.value = value;
            return this;
        }

        public BasePublicEncryptionKey createBasePublicEncryptionKey()
        {
            return new BasePublicEncryptionKey(choice, value);
        }
    }

}