package com.github.zhenwei.sdk.util.asn1.cmc;


import ASN1GeneralizedTime;






import CRLReason;


import X500Name;
import java.math.BigInteger;


/**
 * <pre>
 * RevokeRequest ::= SEQUENCE {
 *     issuerName            Name,
 *     serialNumber          INTEGER,
 *     reason                CRLReason,
 *     invalidityDate         GeneralizedTime OPTIONAL,
 *     passphrase            OCTET STRING OPTIONAL,
 *     comment               UTF8String OPTIONAL }
 * </pre>
 */
public class RevokeRequest
    extends ASN1Object
{
    private final X500Name name;
    private final ASN1Integer serialNumber;
    private final CRLReason reason;

    private ASN1GeneralizedTime invalidityDate;
    private ASN1OctetString passphrase;
    private ASN1UTF8String comment;

    public RevokeRequest(X500Name name,
                         ASN1Integer serialNumber,
                         CRLReason reason,
                         ASN1GeneralizedTime invalidityDate,
                         ASN1OctetString passphrase,
                         ASN1UTF8String comment)
    {
        this.name = name;
        this.serialNumber = serialNumber;
        this.reason = reason;
        this.invalidityDate = invalidityDate;
        this.passphrase = passphrase;
        this.comment = comment;
    }

    private RevokeRequest(ASN1Sequence seq)
    {
        if (seq.size() < 3 || seq.size() > 6)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.name = X500Name.getInstance(seq.getObjectAt(0));
        this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1));
        this.reason = CRLReason.getInstance(seq.getObjectAt(2));

        int index = 3;
        if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof ASN1GeneralizedTime)
        {
            this.invalidityDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(index++));
        }
        if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof ASN1OctetString)
        {
            this.passphrase = ASN1OctetString.getInstance(seq.getObjectAt(index++));
        }
        if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() instanceof ASN1UTF8String)
        {
            this.comment = ASN1UTF8String.getInstance(seq.getObjectAt(index));
        }
    }

    public static cmc.RevokeRequest getInstance(Object o)
    {
        if (o instanceof cmc.RevokeRequest)
        {
            return (cmc.RevokeRequest)o;
        }

        if (o != null)
        {
            return new cmc.RevokeRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public X500Name getName()
    {
        return name;
    }

    public BigInteger getSerialNumber()
    {
        return serialNumber.getValue();
    }

    public CRLReason getReason()
    {
        return reason;
    }

    public ASN1GeneralizedTime getInvalidityDate()
    {
        return invalidityDate;
    }

    public void setInvalidityDate(ASN1GeneralizedTime invalidityDate)
    {
        this.invalidityDate = invalidityDate;
    }

    public ASN1OctetString getPassphrase()
    {
        return passphrase;
    }

    public void setPassphrase(ASN1OctetString passphrase)
    {
        this.passphrase = passphrase;
    }

    /**
     * @deprecated Use {@link #getCommentUTF8()} instead.
     */
    public DERUTF8String getComment()
    {
        return null == comment || comment instanceof DERUTF8String
            ?   (DERUTF8String)comment
            :   new DERUTF8String(comment.getString());
    }

    public ASN1UTF8String getCommentUTF8()
    {
        return comment;
    }

    public void setComment(ASN1UTF8String comment)
    {
        this.comment = comment;
    }

    public byte[] getPassPhrase()
    {
        if (passphrase != null)
        {
            return Arrays.clone(passphrase.getOctets());
        }
        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(6);

        v.add(name);
        v.add(serialNumber);
        v.add(reason);

        if (invalidityDate != null)
        {
            v.add(invalidityDate);
        }
        if (passphrase != null)
        {
            v.add(passphrase);
        }
        if (comment != null)
        {
            v.add(comment);
        }

        return new DERSequence(v);
    }
}