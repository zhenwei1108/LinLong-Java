package com.github.zhenwei.sdk.util.oer.its;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * <pre>
 *     SequenceOfCertificate ::= SEQUENCE OF Certificate
 * </pre>
 */
public class SequenceOfCertificate
    extends ASN1Object
{

    private final List<Certificate> certificates;

    public SequenceOfCertificate(List<Certificate> certificates)
    {
        this.certificates = Collections.unmodifiableList(certificates);
    }

    public static SequenceOfCertificate getInstance(Object src)
    {
        if (src instanceof SequenceOfCertificate)
        {
            return (SequenceOfCertificate)src;
        }

        Iterator<ASN1Encodable> seq = ASN1Sequence.getInstance(src).iterator();
        List<Certificate> certificates = new ArrayList<Certificate>();
        while (seq.hasNext())
        {
            certificates.add(Certificate.getInstance(seq.next()));
        }

        return new SequenceOfCertificate(certificates);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(certificates);
    }

    public List<Certificate> getCertificates()
    {
        return certificates;
    }

    public static class Builder
    {
        List<Certificate> certificates = new ArrayList<Certificate>();

        public Builder add(Certificate... certificates)
        {
            this.certificates.addAll(Arrays.asList(certificates));
            return this;
        }

        public SequenceOfCertificate build()
        {
            return new SequenceOfCertificate(certificates);
        }
    }

}