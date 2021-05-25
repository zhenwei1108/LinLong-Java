package org.sdk.crypto.sign;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.digest.SHA1.Digest;
import org.bouncycastle.jce.provider.asymmetric.ec.ECUtil;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.sdk.crypto.enums.AsymmetryKeyEnum;
import org.sdk.crypto.enums.DigestEnum;
import org.sdk.crypto.enums.SignAlgorithmEnum;
import org.sdk.crypto.init.InitProvider;
import org.sdk.crypto.utils.Base64Util;

public class SignData extends InitProvider {


  public void sign(SignAlgorithmEnum signAlgorithmEnum){

  }


  public static void main(String[] args) throws Exception {
    AsymmetryKeyEnum alg = AsymmetryKeyEnum.SM2;
    KeyPairGenerator generator = KeyPairGenerator.getInstance(alg.getAlg(), BC_PROVIDER);
    //指定曲线
    AlgorithmParameterSpec algorithmParameterSpec = new ECNamedCurveGenParameterSpec("sm2p256v1");
    generator.initialize(algorithmParameterSpec);
    KeyPair keyPair = generator.generateKeyPair();
    System.out.println("公钥："+Base64Util.encodeToString(keyPair.getPublic().getEncoded()));

    MessageDigest sm3 = Digest.getInstance(DigestEnum.SM3.name(), BC_PROVIDER);
    sm3.update("asdf".getBytes(StandardCharsets.UTF_8));
    byte[] digest = sm3.digest();
    System.out.println(digest.length);
    System.out.println(Base64Util.encodeToString(digest));

    AsymmetricKeyParameter asymmetricKeyParameter = ECUtil
        .generatePrivateKeyParameter(keyPair.getPrivate());
    SM2Signer sm2Signer = new SM2Signer();
    sm2Signer.init(true,asymmetricKeyParameter);
    sm2Signer.update(digest,0,digest.length);
    byte[] sign = sm2Signer.generateSignature();

    System.out.println("签名结果："+Base64Util.encodeToString(sign));


  }


}
