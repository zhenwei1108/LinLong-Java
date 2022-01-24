package com.github.zhenwei.pkix.util.asn1.cmc;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERSequence;

/**
 * <pre>
 *       TaggedCertificationRequest ::= SEQUENCE {
 *                  bodyPartID            BodyPartID,
 *                  certificationRequest  CertificationRequest
 *       }
 * </pre>
 */
public class TaggedCertificationRequest
    extends ASN1Object
{
    private final BodyPartID bodyPartID;
    private final CertificationRequest certificationRequest;

    public TaggedCertificationRequest(BodyPartID bodyPartID, CertificationRequest certificationRequest)
    {
        this.bodyPartID = bodyPartID;
        this.certificationRequest = certificationRequest;
    }

    private TaggedCertificationRequest(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
        this.certificationRequest = CertificationRequest.getInstance(seq.getObjectAt(1));
    }

    public static TaggedCertificationRequest getInstance(Object o)
    {
        if (o instanceof TaggedCertificationRequest)
        {
            return (TaggedCertificationRequest)o;
        }

        if (o != null)
        {
            return new TaggedCertificationRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static TaggedCertificationRequest getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(bodyPartID);
        v.add(certificationRequest);

        return new DERSequence(v);
    }
}