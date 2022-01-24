package com.github.zhenwei.pkix.util.asn1.cms;

import com.github.zhenwei.core.asn1.ASN1Choice;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERTaggedObject;
importcom.github.zhenwei.pkix.util.asn1.tsp.EvidenceRecord;

/**
 * <a href="https://tools.ietf.org/html/rfc5544">RFC 5544</a>:
 * Binding Documents with Time-Stamps; Evidence object.
 * <p>
 * <pre>
 * Evidence ::= CHOICE {
 *     tstEvidence    [0] TimeStampTokenEvidence,   -- see RFC 3161
 *     ersEvidence    [1] EvidenceRecord,           -- see RFC 4998
 *     otherEvidence  [2] OtherEvidence
 * }
 * </pre>
 */
public class Evidence
    extends ASN1Object
    implements ASN1Choice
{
    private TimeStampTokenEvidence tstEvidence;
    private EvidenceRecord ersEvidence;
    private ASN1Sequence otherEvidence;

    public Evidence(TimeStampTokenEvidence tstEvidence)
    {
        this.tstEvidence = tstEvidence;
    }

    public Evidence(EvidenceRecord ersEvidence)
    {
        this.ersEvidence = ersEvidence;
    }

    private Evidence(ASN1TaggedObject tagged)
    {
        if (tagged.getTagNo() == 0)
        {
            this.tstEvidence = TimeStampTokenEvidence.getInstance(tagged, false);
        }
        else if (tagged.getTagNo() == 1)
        {
            this.ersEvidence = EvidenceRecord.getInstance(tagged, false);
        }
        else if (tagged.getTagNo() == 2)
        {
            this.otherEvidence = ASN1Sequence.getInstance(tagged, false);
        }
        else
        {
            throw new IllegalArgumentException("unknown tag in Evidence");
        }
    }

    /**
     * Return an Evidence object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> {@link Evidence} object
     * <li> {@link com.github.zhenwei.core.asn1.ASN1TaggedObject#getInstance(Object) ASN1TaggedObject} input formats with Evidence data inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static Evidence getInstance(Object obj)
    {
        if (obj == null || obj instanceof Evidence)
        {
            return (Evidence)obj;
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new Evidence(ASN1TaggedObject.getInstance(obj));
        }

        throw new IllegalArgumentException("unknown object in getInstance");
    }

    public static Evidence getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(obj.getObject()); // must be explicitly tagged
    }

    public TimeStampTokenEvidence getTstEvidence()
    {
        return tstEvidence;
    }

    public EvidenceRecord getErsEvidence()
        {
            return ersEvidence;
        }

    public ASN1Primitive toASN1Primitive()
    {
        if (tstEvidence != null)
        {
            return new DERTaggedObject(false, 0, tstEvidence);
        }
        if (ersEvidence != null)
        {
            return new DERTaggedObject(false, 1, ersEvidence);
        }

        return new DERTaggedObject(false, 2, otherEvidence);
    }
}