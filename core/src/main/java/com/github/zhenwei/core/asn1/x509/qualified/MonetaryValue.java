package com.github.zhenwei.core.asn1.qualified;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import java.math.BigInteger;
import java.util.Enumeration;
import qualified.Iso4217CurrencyCode;

/**
 * The MonetaryValue object.
 * <pre>
 * MonetaryValue  ::=  SEQUENCE {
 *       currency              Iso4217CurrencyCode,
 *       amount               INTEGER, 
 *       exponent             INTEGER }
 * -- value = amount * 10^exponent
 * </pre>
 */
public class MonetaryValue 
    extends ASN1Object
{
    private Iso4217CurrencyCode currency;
    private ASN1Integer amount;
    private ASN1Integer         exponent;
        
    public static qualified.MonetaryValue getInstance(
        Object obj)
    {
        if (obj instanceof qualified.MonetaryValue)
        {
            return (qualified.MonetaryValue)obj;
        }

        if (obj != null)
        {
            return new qualified.MonetaryValue(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    }
        
    private MonetaryValue(
        ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();    
        // currency
        currency = Iso4217CurrencyCode.getInstance(e.nextElement());
        // hashAlgorithm
        amount = ASN1Integer.getInstance(e.nextElement());
        // exponent
        exponent = ASN1Integer.getInstance(e.nextElement());            
    }
        
    public MonetaryValue(
        Iso4217CurrencyCode currency, 
        int                 amount, 
        int                 exponent)
    {    
        this.currency = currency;
        this.amount = new ASN1Integer(amount);
        this.exponent = new ASN1Integer(exponent);
    }                    
             
    public Iso4217CurrencyCode getCurrency()
    {
        return currency;
    }
        
    public BigInteger getAmount()
    {
        return amount.getValue();
    }
        
    public BigInteger getExponent()
    {
        return exponent.getValue();
    }   
    
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector seq = new ASN1EncodableVector(3);
        seq.add(currency);
        seq.add(amount);
        seq.add(exponent); 
        
        return new DERSequence(seq);
    }
}