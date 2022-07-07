package com.github.zhenwei.core.enums;

public enum ModeEnum implements BaseAlgEnum{
  NONE(false),
  ECB(false),
  CBC(true),
  OFB(true),
  CFB(true),
  GCM(true),
  CCM(true),
  CTR(true),



  ;

  private boolean isNeedIV;

  ModeEnum(boolean isNeedIV) {
    this.isNeedIV = isNeedIV;
  }

  @Override
  public String getAlg() {
    return this.name();
  }

  public boolean isNeedIV() {
    return isNeedIV;
  }
}