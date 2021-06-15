# <Strong>E-pay Revision</Strong>

---

#### Bref theoretical concept about JavaCard™ and implementation examples of common uses of JavaCard™

---

# Theory

---

![APDU Structure](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/APDU%20request%20%26%20response%20structure.jpg)
![Page 1](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/JavaCard_Cryptography_001.png)
![Page 2](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/JavaCard_Cryptography_002.png)
![Page 3](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/JavaCard_Cryptography_003.png)
![Page 4](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/JavaCard_Cryptography_004.png)
![Page 5](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/JavaCard_Cryptography_005.png)

<object data="https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/E%20Pay%20Course%20FULL.pdf" type="application/pdf" width="700px" height="700px">
    <embed src="https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/E%20Pay%20Course%20FULL.pdf">
        <p>See the full PDF course <a href="https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/E%20Pay%20Course%20FULL.pdf">here</a>.</p>
    </embed>
</object>

---

# Exercises

---

## 1) Code using javacard API for creating a dual signature.

#### 1.1 \_01_JCAppDualSignature.java

```
Key pub = KeyBuilder.buildKey(Keybuilder.TYPE_RSA_PUBLIC, Keybuilder.LENGTH_RSA_1024, false)
Key priv = KeyBuilder.buildKey(Keybuilder.TYPE_RSA_PRIVATE, Keybuilder.LENGTH_RSA_1024, false)
KeyPair kp = new KeyPair(KeyPair.ALG_RSA, pub.getSize())
kp.generateKeyPair()
pub = kp.getPublic()
priv = kp.getPrivate()
Signature sign = Signature.getInstance(Signature.ALG_RSA_SHA_PKC, false)
sign.Init(priv, Signature.MODE_SIGN)
short len = sign.Sign(buffer, ISO7816.OFFSSET_CDATA, len, buffer, (short) 0)
apdu.setOutgoingaNDsEND(LEN, (short) 0)


```

#### 1.2 select-com.recap.com.recap.\_01_JCAppDualSignature.script

```
// Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.

// Applet Selection APDU Script
//
// Package:     _01_JCAppDualSignature.com.recap
// Package AID: //aid/0102030405/
// Applet:      com.recap._01_JCAppDualSignature
// Applet AID:  //aid/0102030405/01
//

// Select com.recap._01_JCAppDualSignature applet
0x00 0xA4 0x04 0x00 0x06 0x01 0x02 0x03 0x04 0x05 0x01 0x7F;
```

---

## 2) HMAC

#### 2.1 \_02_JCAppHMAC.java

```
byte[] buffer = apdu.getBuffer();
byte[] key = new byte[64];
Util.arrayFill(key, (short)0, (short)64, (byte)0x61);
Signature hmc = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
HMACKey hkey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_HMAC, KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
hkey.setKey(key, (short)0, (short)64);
hmc.init(hkey, Signature.MODE_SIGN);
short ret = hmc.sign(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);
apdu.setOutgoingAndSend((short) 0, ret);
```

#### 2.2 select-com.recap.com.recap.\_02_JCAppHMAC.script

```
// Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.

// Applet Selection APDU Script
//
// Package:     _02_JCAppHMAC.com.recap
// Package AID: //aid/0102030405/
// Applet:      com.recap._02_JCAppHMAC
// Applet AID:  //aid/0102030405/01
//

// Select com.recap._02_JCAppHMAC applet
0x00 0xA4 0x04 0x00 0x06 0x01 0x02 0x03 0x04 0x05 0x01 0x7F;
```

---

## 3) RSA verify

#### 3.1 \_03_JCAppRSAVerify.java

```
Signature sign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false)
sign.Init(PublicKey, Signature.MODE_VERIFY)
short len = sign.Verify(buffer, ISO7816.OFFSSET_CDATA, len, buffer, (short) 0)

```

#### 3.2 select-com.recap.com.recap.\_03_JCAppRSAVerify.script

```
// Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.

// Applet Selection APDU Script
//
// Package:     _03_JCAppRSAVerify.com.recap
// Package AID: //aid/0102030405/
// Applet:      com.recap._03_JCAppRSAVerify
// Applet AID:  //aid/0102030405/01
//

// Select com.recap._03_JCAppRSAVerify applet
0x00 0xA4 0x04 0x00 0x06 0x01 0x02 0x03 0x04 0x05 0x01 0x7F;
```

---

## 4) Signature verification

#### 4.1 \_04_JCAppSignatureVerification.java

```
Key pub = KeyBuilder.buildKey(Keybuilder.TYPE_RSA_PUBLIC, Keybuilder.LENGTH_RSA_1024, false)
Key priv = KeyBuilder.buildKey(Keybuilder.TYPE_RSA_PRIVATE, Keybuilder.LENGTH_RSA_1024, false)
pub.getPublic(); priv.getPrivate();
Signature mSign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
mSign.init(pub, Signature.MODE_VERIFY);

mSign.update(buffer, offset_cdata, len);
Boolean mVerify = mSign.verify(buffer, ISO7816.OFFSET_CDATA, datalen, buffer, (short) 0, signlen);
Apdu.setOutgoingAndSend(mVerify, (short) 0);
```

#### 4.2 select-com.recap.com.recap.\_04_JCAppSignatureVerification.script

```
// Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.

// Applet Selection APDU Script
//
// Package:     _04_JCAppSignatureVerification.com.recap
// Package AID: //aid/0102030405/
// Applet:      com.recap._04_JCAppSignatureVerification
// Applet AID:  //aid/0102030405/01
//

// Select com.recap._04_JCAppSignatureVerification applet
0x00 0xA4 0x04 0x00 0x06 0x01 0x02 0x03 0x04 0x05 0x01 0x7F;
```

---
