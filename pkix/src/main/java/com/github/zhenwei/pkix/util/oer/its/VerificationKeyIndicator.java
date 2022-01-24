package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Choice;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERTaggedObject;

/**
 * <pre>
 *     VerificationKeyIndicator ::= CHOICE {
 *         verificationKey PublicVerificationKey,
 *         reconstructionValue EccP256CurvePoint,
 *         ...
 *     }
 * </pre>
 */
public class VerificationKeyIndicator
    extends ASN1Object
    implements ASN1Choice
{
    public static final int verificationKey = 0;
    public static final int reconstructionValue = 1;
    public static final int extension = 2;

    private final int choice;
    private final ASN1Encodable object;

    public VerificationKeyIndicator(int choice, ASN1Encodable object)
    {
        this.choice = choice;
        this.object = object;
    }

    public static VerificationKeyIndicator getInstance(Object objectAt)
    {
        if (objectAt instanceof VerificationKeyIndicator)
        {
            return (VerificationKeyIndicator)objectAt;
        }

        ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(objectAt);
        switch (taggedObject.getTagNo())
        {
        case verificationKey:
            return new Builder()
                .setChoice(verificationKey)
                .setObject(PublicVerificationKey.getInstance(taggedObject.getObject()))
                .createVerificationKeyIndicator();
        case reconstructionValue:
            return new Builder()
                .setChoice(reconstructionValue)
                .setObject(EccP256CurvePoint.getInstance(taggedObject.getObject()))
                .createVerificationKeyIndicator();

        case extension:
            return new VerificationKeyIndicator(extension,
                DEROctetString.getInstance(taggedObject.getLoadedObject())
            );
        default:
            throw new IllegalArgumentException("unhandled tag " + taggedObject.getTagNo());
        }

    }

    public static Builder builder()
    {
        return new Builder();
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getObject()
    {
        return object;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, object);
    }

    public static class Builder
    {

        private int choice;
        private ASN1Encodable object;

        public Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder setObject(ASN1Encodable object)
        {
            this.object = object;
            return this;
        }

        public Builder publicVerificationKey(PublicVerificationKey publicVerificationKey)
        {
            this.object = publicVerificationKey;
            this.choice = verificationKey;
            return this;
        }

        public Builder reconstructionValue(EccP256CurvePoint curvePoint)
        {
            this.object = curvePoint;
            this.choice = reconstructionValue;
            return this;
        }

        public Builder extension(byte[] value)
        {
            this.object = new DEROctetString(value);
            this.choice = extension;
            return this;
        }


        public VerificationKeyIndicator createVerificationKeyIndicator()
        {
            return new VerificationKeyIndicator(choice, object);
        }
    }
}