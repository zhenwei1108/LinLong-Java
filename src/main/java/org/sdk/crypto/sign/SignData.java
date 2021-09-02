package org.sdk.crypto.sign;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import org.sdk.crypto.enums.SignAlgorithmEnum;
import org.sdk.crypto.exception.CryptoSDKException;
import org.sdk.crypto.exception.ErrorEnum;
import org.sdk.crypto.init.InitProvider;
import org.sdk.crypto.key.asymmetric.AsymmetryKey;
import org.sdk.crypto.key.asymmetric.AsymmetryKeyEnums;

public class SignData extends InitProvider {


  public static byte[] sign(SignAlgorithmEnum signAlgorithmEnum, PrivateKey key, byte[] data) {
    try {
      Signature signature = Signature.getInstance(signAlgorithmEnum.name(), BC_PROVIDER);
      signature.initSign(key);
      signature.update(data);
      return signature.sign();
    } catch (Exception e) {
      throw new CryptoSDKException(ErrorEnum.SIGN_DATA_ERROR, e);
    }
  }


  public static void main(String[] args) throws Exception {
    KeyPair keyPair = AsymmetryKey.genKeyPair(AsymmetryKeyEnums.RSA_1024);
    Signature signature = Signature.getInstance("SHA1WITHRSA", BC_PROVIDER);
    signature.initSign(keyPair.getPrivate());
    signature.update("dfa".getBytes(StandardCharsets.UTF_8));
    byte[] sign = signature.sign();

//    AsymmetryKeyEnum alg = AsymmetryKeyEnum.RSA_1024;
//    KeyPairGenerator generator = KeyPairGenerator.getInstance(alg.getAlg(), BC_PROVIDER);
//    //指定曲线
//    AlgorithmParameterSpec algorithmParameterSpec = new ECNamedCurveGenParameterSpec("sm2p256v1");
//    generator.initialize(algorithmParameterSpec);
//    KeyPair keyPair = generator.generateKeyPair();
//    System.out.println("公钥："+Base64Util.encodeToString(keyPair.getPublic().getEncoded()));
//
//    MessageDigest sm3 = Digest.getInstance(DigestEnum.SM3.name(), BC_PROVIDER);
//    sm3.update("asdf".getBytes(StandardCharsets.UTF_8));
//    byte[] digest = sm3.digest();
//    System.out.println(digest.length);
//    System.out.println(Base64Util.encodeToString(digest));
//
//    AsymmetricKeyParameter asymmetricKeyParameter = ECUtil
//        .generatePrivateKeyParameter(keyPair.getPrivate());
//    SM2Signer sm2Signer = new SM2Signer();
//    sm2Signer.init(true,asymmetricKeyParameter);
//    sm2Signer.update(digest,0,digest.length);
//    byte[] sign = sm2Signer.generateSignature();
//
//    System.out.println("签名结果："+Base64Util.encodeToString(sign));

  }


}
