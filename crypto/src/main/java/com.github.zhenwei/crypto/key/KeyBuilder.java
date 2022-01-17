package org.sdk.crypto.key;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class KeyBuilder {


  public static PublicKey buildByteToKey(String alg, byte[] key)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyFactory factory = KeyFactory.getInstance(alg);
    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
    PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);
    return publicKey;
  }


  public static PublicKey buildRsaPubKey() {
    PublicKey publicKey = null;

    return publicKey;
  }


  public static void buildRsaPriKey()
      throws IOException {
    byte[] byteD = Hex.decode(
        "84f6a2e6ca2b5c94db0208d018141dd71f35c2db084d0585891a89b526069c1d69e6de54fffe1b81349c6f5478eb897462c2b3a22ba84e04aab41a12ae8c85606c1d2fb47944c26d288bbb853c146a5d9c3bd69fe1c9db044b752fc81e4f5324b208f15f57935ec5473a89f71c13250371d68815789693ff323093eee6420041");
    byte[] bytePrime1 = Hex
        .decode(
            "eab75afe200e7cb4bfd9299c45fe4f130bf779cd58de43aa866a83d72eda9276c79f99399b317a1dae20949a0ec01eb0f99a8d27e9132bd5edbcc8220d054f8d");
    byte[] bytePrime2 = Hex
        .decode(
            "db79ecd8c994715f9eb79e45f5fe26958dccf146e140a4b52416570d36b003df944bff336edbd5b6714242982f9fe30ea277490523b8fb924096e19622cf785f");
    byte[] byteExport1 = Hex
        .decode(
            "e7120183a2fd8029d5a12e44c9e775e373697c40fbd73cd879220d8f5f7210b4dd0bb3263231c05dcdda0751af69d60d367dbfaf65d6d8d5f0096521989dfcd5");

    byte[] byteExport2 = Hex
        .decode(
            "d908159d3ea12b079a650aff35c570143dd7e6d3e7954c0ad037c3378ed7b9ccd2d1dff7d56d50458c7430745bcbe8f524d57e80b5958c3850e4a3091b3d3c53");
    byte[] byteCoef = Hex
        .decode(
            "d7d36336cf9a52e9a463ea31b4f87fad4a739acfd41a2951276dd78c88a6b183822079f282a3ad2db9213b91e9f631f11f167c9cf73aca024f0f0239a94b738d");

    BigInteger d = new BigInteger(byteD);

    BigInteger prime1 = new BigInteger(bytePrime1);
    BigInteger prime2 = new BigInteger(bytePrime2);
    BigInteger export1 = new BigInteger(byteExport1);
    BigInteger export2 = new BigInteger(byteExport2);
    BigInteger coef = new BigInteger(byteCoef);
    BigInteger e = new BigInteger("65537");
    BigInteger moudle = new BigInteger("1024");
    BigInteger zero = new BigInteger("0");

    RSAPrivateKey rsaPrivateKey = new RSAPrivateKey(moudle, e, d, prime1, prime2, export1, export2,
        coef);
    byte[] encoded = rsaPrivateKey.getEncoded();

    System.out.println(Base64.toBase64String(encoded));

    BigInteger prime11 = rsaPrivateKey.getPrime1();
    BigInteger modulus = rsaPrivateKey.getModulus();

  }
}