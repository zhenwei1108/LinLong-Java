package org.sdk.crypto.sign;

 
 
import SM2Signer;
import org.bouncycastle.jce.provider.asymmetric.ec.ECUtil;
import org.sdk.crypto.init.InitProvider;

import java.security.InvalidKeyException;
import java.security.PrivateKey;

public class Sm2Signer extends InitProvider {

    /**
     * 默认userid = 1234567812345678
     * @param data
     * @param privateKey
     * @return
     * @throws InvalidKeyException
     * @throws CryptoException
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws InvalidKeyException, CryptoException {
        //TODO 根据私钥计算公钥
        AsymmetricKeyParameter asymmetricKeyParameter = ECUtil.generatePrivateKeyParameter(privateKey);
        SM2Signer sm2Signer = new SM2Signer();
        sm2Signer.init(true, asymmetricKeyParameter);
        sm2Signer.update(data, 0, data.length);
        return sm2Signer.generateSignature();

    }

}