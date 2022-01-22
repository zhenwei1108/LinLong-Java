package com.github.zhenwei.sdk.util.oer.its;









/**
 * <pre>
 *     Signature ::= CHOICE {
 *         ecdsaNistP256Signature EcdsaP256Signature,
 *         ecdsaBrainpoolP256r1Signature EcdsaP256Signature,
 *         ...
 *         ecdsaBrainpoolP384r1Signature EcdsaP384Signature
 *     }
 * </pre>
 */
public class Signature
    extends ASN1Object
    implements ASN1Choice
{
    public static final int ecdsaNistP256Signature = 0;
    public static final int ecdsaBrainpoolP256r1Signature = 1;
    public static final int ecdsaBrainpoolP384r1Signature = 3;
    private static final int extension = 2;
    private final int choice;
    private final ASN1Encodable value;

    public Signature(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
    }

    public static Signature getInstance(Object objectAt)
    {
        if (objectAt instanceof Signature)
        {
            return (Signature)objectAt;
        }

        ASN1TaggedObject ato = ASN1TaggedObject.getInstance(objectAt);
        ASN1Encodable value;

        switch (ato.getTagNo())
        {
        case ecdsaNistP256Signature:
        case ecdsaBrainpoolP256r1Signature:
            value = EcdsaP256Signature.getInstance(ato.getObject());
            break;
        case extension:
            value = DEROctetString.getInstance(ato.getObject());
            break;
        case ecdsaBrainpoolP384r1Signature:
            value = EcdsaP384Signature.getInstance(ato.getObject());
            break;
        default:
            throw new IllegalStateException("unknown choice " + ato.getTagNo());
        }
        return new Signature(ato.getTagNo(), value);

    }

    public static Builder builder()
    {
        return new Builder();
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
/*
    ecdsaNistP256Signature EcdsaP256Signature,
 *         ecdsaBrainpoolP256r1Signature EcdsaP256Signature,
 *         ...
 *         ecdsaBrainpoolP384r1Signature EcdsaP384Signature
 */

        public Builder ecdsaNistP256Signature(EcdsaP256Signature signature)
        {
            choice = ecdsaNistP256Signature;
            value = signature;
            return this;
        }

        public Builder ecdsaBrainpoolP256r1Signature(EcdsaP256Signature signature)
        {
            choice = ecdsaBrainpoolP256r1Signature;
            value = signature;
            return this;
        }

        public Builder ecdsaBrainpoolP384r1Signature(EcdsaP384Signature signature)
        {
            choice = ecdsaBrainpoolP384r1Signature;
            value = signature;
            return this;
        }

        public Signature createSignature()
        {
            return new Signature(choice, value);
        }
    }

}