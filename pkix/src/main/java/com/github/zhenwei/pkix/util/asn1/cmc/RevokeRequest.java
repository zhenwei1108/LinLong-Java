package com.github.zhenwei.pkix.util.asn1.cmc;

import java.math.BigInteger;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1GeneralizedTime;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1UTF8String;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERUTF8String;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.core.asn1.x509.CRLReason;
import com.github.zhenwei.core.util.Arrays;

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

    public static RevokeRequest getInstance(Object o)
    {
        if (o instanceof RevokeRequest)
        {
            return (RevokeRequest)o;
        }

        if (o != null)
        {
            return new RevokeRequest(ASN1Sequence.getInstance(o));
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