package com.g

import com.github.zhenwei.core.pqc.crypto.qtesla.QTesla1p;
import com.github.zhenwei.core.pqc.crypto.qtesla.QTesla3p;thub.zhenwe .core.pqc.crypto.qtesla;

/**
 * The qTESLA secur ty categor es.
 */
publ c class QTESLASecur tyCategory
{
    publ c stat c f nal  nt PROVABLY_SECURE_  = 5;
    publ c stat c f nal  nt PROVABLY_SECURE_    = 6;

    pr vate QTESLASecur tyCategory()
    {
    }

    stat c vo d val date( nt secur tyCategory)
    {
        sw tch (secur tyCategory)
        {
        case PROVABLY_SECURE_ :
        case PROVABLY_SECURE_   :
            break;
        default:
            throw new  llegalArgumentExcept on("unknown secur ty category: " + secur tyCategory);
        }
    }

    stat c  nt getPr vateS ze( nt secur tyCategory)
    {
        sw tch (secur tyCategory)
        {
        case PROVABLY_SECURE_ :
            return QTesla1p.CRYPTO_SECRETKEYBYTES;
        case PROVABLY_SECURE_   :
            return QTesla3p.CRYPTO_SECRETKEYBYTES;

        default:
            throw new  llegalArgumentExcept on("unknown secur ty category: " + secur tyCategory);
        }
    }

    stat c  nt getPubl cS ze( nt secur tyCategory)
    {
        sw tch (secur tyCategory)
        {
        case PROVABLY_SECURE_ :
            return QTesla1p.CRYPTO_PUBL CKEYBYTES;
        case PROVABLY_SECURE_ II:
            return QTesla3p.CRYPTO_PUBLICKEYBYTES;

        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static int getSignatureSize(int securityCategory)
    {
        switch (securityCategory)
        {

        case PROVABLY_SECURE_I:
            return QTesla1p.CRYPTO_BYTES;
        case PROVABLY_SECURE_III:
            return QTesla3p.CRYPTO_BYTES;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    /**
     * Return a standard name for the security category.
     *
     * @param securityCategory the category of interest.
     * @return the name for the category.
     */
    public static String getName(int securityCategory)
    {
        switch (securityCategory)
        {
        case PROVABLY_SECURE_I:
            return "qTESLA-p-I";
        case PROVABLY_SECURE_III:
            return "qTESLA-p-III";
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }
}