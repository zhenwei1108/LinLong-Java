package org.sdk.crypto.sign;

import org.sdk.crypto.enums.SignAlgorithmEnum;
import org.sdk.crypto.exception.CryptoSDKException;
import org.sdk.crypto.exception.ErrorEnum;
import org.sdk.crypto.init.InitProvider;
import org.sdk.crypto.key.asymmetric.AsymmetryKey;
import org.sdk.crypto.key.asymmetric.AsymmetryKeyEnums;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class RsaSigner extends InitProvider {


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

  public static byte[] sign(SignAlgorithmEnum signAlgorithmEnum, PrivateKey key, byte[] data, Provider provider) {
    try {
      Signature signature = Signature.getInstance(signAlgorithmEnum.name(), provider);
      signature.initSign(key);
      signature.update(data);
      return signature.sign();
    } catch (Exception e) {
      throw new CryptoSDKException(ErrorEnum.SIGN_DATA_ERROR, e);
    }
  }

  public static boolean verifySignedData(String alg, byte[] signData, byte[] sourceData, PublicKey key)
          throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
    Signature signature = Signature.getInstance(alg, BC_PROVIDER);
    signature.initVerify(key);
    signature.update(sourceData);
    return signature.verify(signData);
  }

  public static boolean verifySignedData(String alg, byte[] signData, byte[] sourceData, PublicKey key, Provider provider)
          throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature signature = Signature.getInstance(alg, provider);
    signature.initVerify(key);
    signature.update(sourceData);
    return signature.verify(signData);
  }





  public static void main(String[] args) throws Exception {
    KeyPair keyPair = AsymmetryKey.genKeyPair(AsymmetryKeyEnums.RSA_1024);
    Signature signature = Signature.getInstance("SHA1WITHRSA", BC_PROVIDER);
    signature.initSign(keyPair.getPrivate());
    signature.update("dfa".getBytes(StandardCharsets.UTF_8));
    byte[] sign = signature.sign();

//    AsymmetryKeyEnum alg = AsymmetryKeyEnum.RSA_1024;
//    KeyPairGenerator generator = KeyPairGenerator.getInstance(alg.getAlg(), BC_PROVIDER);


  }


}