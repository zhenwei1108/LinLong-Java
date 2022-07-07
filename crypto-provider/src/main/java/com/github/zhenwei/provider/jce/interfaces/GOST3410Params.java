package com.github.zhenwei.provider.jce.interfaces;

import com.github.zhenwei.provider.jce.spec.GOST3410PublicKeyParameterSetSpec;

public interface GOST3410Params {

  public String getPublicKeyParamSetOID();

  public String getDigestParamSetOID();

  public String getEncryptionParamSetOID();

  public GOST3410PublicKeyParameterSetSpec getPublicKeyParameters();
}