package com.github.zhenwei.pkix.pkix.jcajce;

import org.bouncycastle.asn1.x509.ReasonFlags;

/**
 * This class helps to handle CRL revocation reasons mask. Each CRL handles a
 * certain set of revocation reasons.
 */
class ReasonsMask
{
    private int _reasons;

    /**
     * Constructs are reason mask with the reasons.
     * 
     * @param reasons The reasons.
     */
    ReasonsMask(ReasonFlags reasons)
    {
        _reasons = reasons.intValue();
    }

    private ReasonsMask(int reasons)
    {
        _reasons = reasons;
    }

    /**
     * A reason mask with no reason.
     * 
     */
    ReasonsMask()
    {
        this(0);
    }

    /**
     * A mask with all revocation reasons.
     */
    static final org.bouncycastle.pkix.jcajce.ReasonsMask allReasons = new org.bouncycastle.pkix.jcajce.ReasonsMask(ReasonFlags.aACompromise
            | ReasonFlags.affiliationChanged | ReasonFlags.cACompromise
            | ReasonFlags.certificateHold | ReasonFlags.cessationOfOperation
            | ReasonFlags.keyCompromise | ReasonFlags.privilegeWithdrawn
            | ReasonFlags.unused | ReasonFlags.superseded);

    /**
     * Adds all reasons from the reasons mask to this mask.
     * 
     * @param mask The reasons mask to add.
     */
    void addReasons(org.bouncycastle.pkix.jcajce.ReasonsMask mask)
    {
        _reasons = _reasons | mask.getReasons();
    }

    /**
     * Returns <code>true</code> if this reasons mask contains all possible
     * reasons.
     * 
     * @return <code>true</code> if this reasons mask contains all possible
     *         reasons.
     */
    boolean isAllReasons()
    {
        return _reasons == allReasons._reasons ? true : false;
    }

    /**
     * Intersects this mask with the given reasons mask.
     * 
     * @param mask The mask to intersect with.
     * @return The intersection of this and teh given mask.
     */
    org.bouncycastle.pkix.jcajce.ReasonsMask intersect(org.bouncycastle.pkix.jcajce.ReasonsMask mask)
    {
        org.bouncycastle.pkix.jcajce.ReasonsMask _mask = new org.bouncycastle.pkix.jcajce.ReasonsMask();
        _mask.addReasons(new org.bouncycastle.pkix.jcajce.ReasonsMask(_reasons & mask.getReasons()));
        return _mask;
    }

    /**
     * Returns <code>true</code> if the passed reasons mask has new reasons.
     * 
     * @param mask The reasons mask which should be tested for new reasons.
     * @return <code>true</code> if the passed reasons mask has new reasons.
     */
    boolean hasNewReasons(org.bouncycastle.pkix.jcajce.ReasonsMask mask)
    {
        return ((_reasons | mask.getReasons() ^ _reasons) != 0);
    }

    /**
     * Returns the reasons in this mask.
     * 
     * @return Returns the reasons.
     */
    int getReasons()
    {
        return _reasons;
    }
}