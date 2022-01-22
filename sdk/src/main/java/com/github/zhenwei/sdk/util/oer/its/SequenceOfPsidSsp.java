package com.github.zhenwei.sdk.util.oer.its;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * SequenceOfPsidSsp ::= SEQUENCE OF PsidSsp
 */
public class SequenceOfPsidSsp
    extends ASN1Object
{
    private final List<PsidSsp> items;

    public SequenceOfPsidSsp(List<PsidSsp> items)
    {
        this.items = Collections.unmodifiableList(items);
    }

    public static SequenceOfPsidSsp getInstance(Object o)
    {
        if (o instanceof SequenceOfPsidSsp)
        {
            return (SequenceOfPsidSsp)o;
        }
        ASN1Sequence sequence = ASN1Sequence.getInstance(o);
        Enumeration e = sequence.getObjects();
        ArrayList<PsidSsp> accumulator = new ArrayList<PsidSsp>();
        while (e.hasMoreElements())
        {
            accumulator.add(PsidSsp.getInstance(e.nextElement()));
        }
        return new Builder().setItems(accumulator).createSequenceOfPsidSsp();
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public List<PsidSsp> getItems()
    {
        return items;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector avec = new ASN1EncodableVector();
        for (PsidSsp ssp : items)
        {
            avec.add(ssp);
        }

        return new DERSequence(avec);
    }

    public static class Builder
    {

        private List<PsidSsp> items = new ArrayList<PsidSsp>();

        public Builder setItems(List<PsidSsp> items)
        {
            this.items = items;
            return this;
        }

        public Builder setItem(PsidSsp... items)
        {
            for (PsidSsp item : items)
            {
                this.items.add(item);
            }
            return this;
        }

        public SequenceOfPsidSsp createSequenceOfPsidSsp()
        {
            return new SequenceOfPsidSsp(items);
        }
    }
}