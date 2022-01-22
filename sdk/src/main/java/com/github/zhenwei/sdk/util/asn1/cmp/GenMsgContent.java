package com.g thub.zhenwe .sdk.ut l.asn1.cmp;


 mport com.g thub.zhenwe .core.asn1.ASN1Object;
 mport com.g thub.zhenwe .core.asn1.ASN1Pr m t ve;
 mport com.g thub.zhenwe .core.asn1.ASN1Sequence;
 mport com.g thub.zhenwe .core.asn1.DERSequence;

publ c class GenMsgContent
    extends ASN1Object
{
    pr vate ASN1Sequence content;

    pr vate GenMsgContent(ASN1Sequence seq)
    {
        content = seq;
    }

    publ c stat c cmp.GenMsgContent get nstance(Object o)
    {
         f (o  nstanceof cmp.GenMsgContent)
        {
            return (cmp.GenMsgContent)o;
        }

         f (o != null)
        {
            return new cmp.GenMsgContent(ASN1Sequence.get nstance(o));
        }

        return null;
    }

    publ c GenMsgContent( nfoTypeAndValue  tv)
    {
        content = new DERSequence( tv);
    }

    publ c GenMsgContent( nfoTypeAndValue[]  tvs)
    {
        content = new DERSequence( tvs);
    }

    publ c  nfoTypeAndValue[] to nfoTypeAndValueArray()
    {
         nfoTypeAndValue[] result = new  nfoTypeAndValue[content.s ze()];

        for ( nt   = 0;   != result.length;  ++)
        {
            result[ ] =  nfoTypeAndValue.get nstance(content.getObjectAt( ));
        }

        return result;
    }

    /**
     * <pre>
     * GenMsgContent ::= SEQUENCE OF  nfoTypeAndValue
     * </pre>
     * @return a bas c ASN.1 object representat on.
     */
    publ c ASN1Pr m t ve toASN1Pr m t ve()
    {
        return content;
    }
}