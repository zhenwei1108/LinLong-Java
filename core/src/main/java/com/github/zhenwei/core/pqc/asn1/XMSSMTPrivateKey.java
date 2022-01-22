package com.github.zhenwei.core.pqc.asn1;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERTaggedObject;
import com.github.zhenwei.core.util.Arrays;

/**
 * XMMSMTPrivateKey
 * <pre>
 *     XMMSMTPrivateKey ::= SEQUENCE {
 *         version INTEGER -- 0, or 1 if maxIndex is present
 *         keyData SEQUENCE {
 *            index         INTEGER
 *            secretKeySeed OCTET STRING
 *            secretKeyPRF  OCTET STRING
 *            publicSeed    OCTET STRING
 *            root          OCTET STRING
 *            maxIndex      [0] INTEGER OPTIONAL
 *         }
 *         bdsState CHOICE {
 *            platformSerialization [0] OCTET STRING
 *         } OPTIONAL
 *    }
 * </pre>
 */
public class XMSSMTPrivateKey
    extends ASN1Object
{
    private final int version;
    private final long index;
    private final long maxIndex;
    private final byte[] secretKeySeed;
    private final byte[] secretKeyPRF;
    private final byte[] publicSeed;
    private final byte[] root;
    private final byte[] bdsState;

    public XMSSMTPrivateKey(long index, byte[] secretKeySeed, byte[] secretKeyPRF, byte[] publicSeed, byte[] root, byte[] bdsState)
    {
        this.version = 0;
        this.index = index;
        this.secretKeySeed = Arrays.clone(secretKeySeed);
        this.secretKeyPRF = Arrays.clone(secretKeyPRF);
        this.publicSeed = Arrays.clone(publicSeed);
        this.root = Arrays.clone(root);
        this.bdsState = Arrays.clone(bdsState);
        this.maxIndex = -1;
    }

    public XMSSMTPrivateKey(long index, byte[] secretKeySeed, byte[] secretKeyPRF, byte[] publicSeed, byte[] root, byte[] bdsState, long maxIndex)
    {
        this.version = 1;
        this.index = index;
        this.secretKeySeed = Arrays.clone(secretKeySeed);
        this.secretKeyPRF = Arrays.clone(secretKeyPRF);
        this.publicSeed = Arrays.clone(publicSeed);
        this.root = Arrays.clone(root);
        this.bdsState = Arrays.clone(bdsState);
        this.maxIndex = maxIndex;
    }

    private XMSSMTPrivateKey(ASN1Sequence seq)
    {
        ASN1Integer v = ASN1Integer.getInstance(seq.getObjectAt(0));
        if (!(v.hasValue(0) || v.hasValue(1)))
        {
            throw new IllegalArgumentException("unknown version of sequence");
        }
        this.version = v.intValueExact();

        if (seq.size() != 2 && seq.size() != 3)
        {
            throw new IllegalArgumentException("key sequence wrong size");
        }

        ASN1Sequence keySeq = ASN1Sequence.getInstance(seq.getObjectAt(1));

        this.index = ASN1Integer.getInstance(keySeq.getObjectAt(0)).longValueExact();
        this.secretKeySeed = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(1)).getOctets());
        this.secretKeyPRF = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(2)).getOctets());
        this.publicSeed = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(3)).getOctets());
        this.root = Arrays.clone(DEROctetString.getInstance(keySeq.getObjectAt(4)).getOctets());

        if (keySeq.size() == 6)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(keySeq.getObjectAt(5));
            if (tagged.getTagNo() != 0)
            {
                throw new IllegalArgumentException("unknown tag in XMSSPrivateKey");
            }
            this.maxIndex = ASN1Integer.getInstance(tagged, false).longValueExact();
        }
        else if (keySeq.size() == 5)
        {
            this.maxIndex = -1;
        }
        else
        {
            throw new IllegalArgumentException("keySeq should be 5 or 6 in length");
        }

        if(seq.size() == 3)
        {
            this.bdsState = Arrays.clone(DEROctetString.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(2)), true).getOctets());
        }
        else
        {
            this.bdsState = null;
        }
    }

    public static org.bouncycastle.pqc.asn1.XMSSMTPrivateKey getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.pqc.asn1.XMSSMTPrivateKey)
        {
            return (org.bouncycastle.pqc.asn1.XMSSMTPrivateKey)o;
        }
        else if (o != null)
        {
            return new org.bouncycastle.pqc.asn1.XMSSMTPrivateKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int getVersion()
    {
        return version;
    }

    public long getIndex()
    {
        return index;
    }

    public long getMaxIndex()
    {
        return maxIndex;
    }

    public byte[] getSecretKeySeed()
    {
        return Arrays.clone(secretKeySeed);
    }

    public byte[] getSecretKeyPRF()
    {
        return Arrays.clone(secretKeyPRF);
    }

    public byte[] getPublicSeed()
    {
        return Arrays.clone(publicSeed);
    }

    public byte[] getRoot()
    {
        return Arrays.clone(root);
    }

    public byte[] getBdsState()
    {
        return Arrays.clone(bdsState);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (maxIndex >= 0)
        {
            v.add(new ASN1Integer(1)); // version 1
        }
        else
        {
            v.add(new ASN1Integer(0)); // version 0
        }

        ASN1EncodableVector vK = new ASN1EncodableVector();

        vK.add(new ASN1Integer(index));
        vK.add(new DEROctetString(secretKeySeed));
        vK.add(new DEROctetString(secretKeyPRF));
        vK.add(new DEROctetString(publicSeed));
        vK.add(new DEROctetString(root));
        if (maxIndex >= 0)
        {
            vK.add(new DERTaggedObject(false, 0, new ASN1Integer(maxIndex)));
        }

        v.add(new DERSequence(vK));
        v.add(new DERTaggedObject(true, 0, new DEROctetString(bdsState)));

        return new DERSequence(v);
    }
}