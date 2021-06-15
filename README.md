# <Strong>E-pay Revision</Strong>

---

#### Bref theoretical concepts about JavaCard™ and implementation examples of common uses of JavaCard™

---

# Theory

---

#### Applet steps:

![APDU Structure](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/Applet%20steps.png)

---

Constraints:

![APDU Structure](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/JC%20VM%20limitations.png)
![APDU Structure](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/framework1.png)

---

#### Java Card API

![APDU Structure](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/framework2.png)

##### Java Card API – javacard.framework.\*

![APDU Structure](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/framework3.png)

##### Java Card API – javacard.framework.service.\*

![APDU Structure](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/framework4.png)

##### Java Card API – javacard.security.\*

![APDU Structure](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/framework5.png)

---

#### APDU structure:

![APDU Structure](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/APDU%20request%20%26%20response%20structure.jpg)
![APDU Structure 2](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/APDU%20Structure%202.png)

---

#### JavaCard Cryptography:

![Page 1](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/JavaCard_Cryptography_001.png)
![Page 2](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/JavaCard_Cryptography_002.png)
![Page 3](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/JavaCard_Cryptography_003.png)
![Page 4](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/JavaCard_Cryptography_004.png)
![Page 5](https://github.com/mmihaipreda/e-pay-recap/blob/master/theory/JavaCard_Cryptography_005.png)

---

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
/**
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 *
 */

package com.recap;

import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.annotations.*;

/**
 * Applet class
 *
 * @author <user>
 */
@StringPool(value = { @StringDef(name = "Package", value = "com.recap"),
		@StringDef(name = "AppletName", value = "_01_JCAppDualSignature") },
		// Insert your strings here
		name = "_01_JCAppDualSignatureStrings")
public class _01_JCAppDualSignature extends Applet {

	static final byte CLA_DUAL_SIGNATURE = (byte) 0x80;
	static final byte INS_GEN_KEYS = (byte) 0x10;
	static final byte INS_SIGN = (byte) 0x20;
	static final byte INS_VERIFY = (byte) 0x30;

	static byte[] verifySignatureBuffer;
	static short offsetInVerifySignature = 0;

	static RSAPublicKey publicKey;
	static RSAPrivateKey privateKey;

	static Signature sign;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new _01_JCAppDualSignature();
	}

	/**
	 * Only this class's install method should create the applet object.
	 */
	protected _01_JCAppDualSignature() {
		sign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

		// Make the verify signature buffer be able to hold the biggest signature we can
		// generate.
		verifySignatureBuffer = JCSystem.makeTransientByteArray((short) (KeyBuilder.LENGTH_RSA_4096 / 8),
				JCSystem.CLEAR_ON_DESELECT);
		register();
	}

	/**
	 * Processes an incoming APDU.
	 *
	 * @see APDU
	 * @param apdu the incoming APDU
	 */
	@Override
	public void process(APDU apdu) {
		if (selectingApplet())
			return;

		byte[] buffer = apdu.getBuffer();

		if (buffer[ISO7816.OFFSET_CLA] != CLA_DUAL_SIGNATURE) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		// Get how much you have in dataIn / CDATA
		short len = apdu.setIncomingAndReceive();

		switch (buffer[ISO7816.OFFSET_INS]) {
		case INS_GEN_KEYS:
			generateKeys(apdu, len);
			break;
		case INS_SIGN:
			sign(apdu, len);
			break;
		case INS_VERIFY:
			verify(apdu, len);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	public void generateKeys(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();

		short rsaKeyLength = 0;
		switch (buffer[ISO7816.OFFSET_P1]) {
		case 0x01:
			rsaKeyLength = KeyBuilder.LENGTH_RSA_512;
			break;
		case 0x02:
			rsaKeyLength = KeyBuilder.LENGTH_RSA_1024;
			break;
		case 0x03:
			rsaKeyLength = KeyBuilder.LENGTH_RSA_2048;
			break;
		case 0x04:
			rsaKeyLength = KeyBuilder.LENGTH_RSA_4096;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, rsaKeyLength);
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		// Set exponent sent by the user.
		publicKey.setExponent(buffer, ISO7816.OFFSET_CDATA, len);

		// The key generating operation takes a longer time, so we should let the host
		// know
		keyPair.genKeyPair();

		this.publicKey = publicKey;
		this.privateKey = privateKey;

		apdu.setOutgoingAndSend((short) ISO7816.OFFSET_CDATA, len);
	}

	public void sign(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();

		sign.init(privateKey, Signature.MODE_SIGN);

		// send 0x80 => has more bytes.
		boolean hasMoreBytes = (buffer[ISO7816.OFFSET_P1] & 0x80) != 0;

		if (hasMoreBytes) {
			sign.update(buffer, ISO7816.OFFSET_CDATA, len);
		} else {
			// Use verifySignatureBuffer as output array for the signature, since it's
			// bigger.
			short signatureLength = sign.sign(buffer, ISO7816.OFFSET_CDATA, len, verifySignatureBuffer, (short) 0);
			apdu.setOutgoing();
			apdu.setOutgoingLength(signatureLength);

			short offsetInSignatureBuffer = 0;

			// Send chunks of 64 bytes (or less than that in the last chunk)
			while (signatureLength > 0) {
				// Get min between signatureLength and 64 (chunk size).
				short bytesToSend = signatureLength < 64 ? signatureLength : 64;
				apdu.sendBytesLong(verifySignatureBuffer, offsetInSignatureBuffer, bytesToSend);
				offsetInSignatureBuffer += bytesToSend;
				signatureLength -= bytesToSend;
			}
		}
	}

	public void verify(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
		sign.init(publicKey, Signature.MODE_VERIFY);

		// send 0x80 => has more bytes.
		boolean hasMoreBytes = (buffer[ISO7816.OFFSET_P1] & 0x80) != 0;

		// send 0x01 => signature bytes. Otherwise, data bytes.
		boolean sentSignatureBytes = (buffer[ISO7816.OFFSET_P2] & 0x01) != 0;

		if (hasMoreBytes) {
			if (sentSignatureBytes) {
				Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, verifySignatureBuffer, offsetInVerifySignature, len);
				offsetInVerifySignature += len;
			} else {
				sign.update(buffer, ISO7816.OFFSET_CDATA, len);
			}
		} else {
			boolean isValid = sign.verify(buffer, // inBuff
					ISO7816.OFFSET_CDATA, // offset at which data is in inBuff
					len, // how many bytes of data are in inBuff
					verifySignatureBuffer, // the buffer in which we stored the signature
					(short) 0, // offset in verifySignatureBuffer
					(short) (publicKey.getSize() / 8)); // signature length (how much we stored in
														// verifySignatureBuffer)

			byte responseByte = isValid ? (byte) 0x01 : (byte) 0x00;
			buffer[0] = responseByte;

			// Reset offset for subsequent verifications.
			offsetInVerifySignature = 0;
			apdu.setOutgoingAndSend((short) 0, (short) 1);
		}
	}
}



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

//generate key pair (sending exponent )
0x80 0x10 0x03 0x00 0x03 0x01 0x00 0x01 0x03;

//sign "test"
0x80 0x20 0x00 0x00 0x04 0x74 0x65 0x73 0x74 0x40;


```

#### 1.3 verify.script

```
// Verify "test"
// Step 1. Send signature. 0x80 P1 => more bytes to send, 0x01 P2 => sending signature.
// 0x80 0x30 0x80 0x01 0x40 0x03 0xa5 0x99 0x7c 0x84 0x1d 0x99 0xa3 0x02 0xca 0xb0 0xc7 0x86 0xf1 0xbd 0x90 0x6c 0x41 0xdb 0x86 0x7f 0x36 0xf2 0xb0 0xda 0xf6 0x63 0xe8 0x20 0x20 0x35 0xbf 0x2d 0x82 0xfd 0x1f 0xf3 0x05 0x96 0xea 0x90 0x06 0xa5 0xac 0x67 0x11 0x0d 0xb2 0x48 0x64 0x6b 0x35 0x89 0x83 0x11 0xb5 0x8c 0x60 0xcb 0x79 0x19 0xc7 0x31 0x06 0x7F;


// Step 2. Send data "test". Only one chunk => 0x00 P1 (no more bytes to send), 0x00 P2 (sending data).
// 0x80 0x30 0x00 0x00 0x04 0x74 0x65 0x73 0x74 0x01;

// Verify "test" with 256 bytes signature (key size is 2048)
// Step 1. Send signature. 0x80 P1 => more bytes to send, 0x01 P2 => sending signature.
0x80 0x30 0x80 0x01 0x40 0x6b 0x43 0x04 0x8d 0x0d 0x81 0x9e 0xa3 0x40 0x1e 0x2a 0xcf 0xc1 0x95 0xe0 0xda 0x47 0x6f 0xe9 0x42 0x0e 0xda 0x5b 0x97 0xae 0x06 0x43 0x96 0x63 0xa9 0x85 0x76 0x5e 0xf1 0xdf 0xbf 0xa9 0xd3 0x4d 0x8f 0x37 0x45 0xfe 0x7a 0x9c 0x08 0xa1 0x5d 0xf8 0xd8 0x8f 0xcc 0x3a 0x7d 0x06 0xe0 0xf9 0x4a 0x19 0x9d 0xca 0xb1 0x95 0x83 0X7F;

0x80 0x30 0x80 0x01 0x40 0xe2 0xff 0xaa 0x5b 0x14 0xfa 0x63 0xa1 0x4c 0x5f 0x37 0x92 0x2e 0xbb 0xd6 0xf1 0x7b 0x8a 0xdd 0xa7 0xd8 0x1e 0x3e 0x11 0xa2 0x8f 0x7f 0x13 0x93 0xb2 0x9a 0x3d 0x8a 0xde 0xae 0xad 0xa0 0xf2 0x93 0x98 0xe9 0x98 0x33 0x61 0x2f 0x68 0xc3 0x74 0xc2 0x59 0x21 0xbd 0x68 0xcd 0xd9 0x53 0xfd 0x58 0x5a 0x01 0x42 0xa7 0x3c 0x25 0x7F;

0x80 0x30 0x80 0x01 0x40 0xef 0x07 0x78 0xab 0x10 0x05 0x11 0x8c 0x90 0xb8 0xd4 0x39 0x7f 0x3b 0x92 0xd5 0x85 0xb5 0xf3 0x2e 0x4b 0x07 0xf3 0xd8 0x95 0x6e 0x4b 0x6a 0x74 0x74 0x64 0x0d 0xec 0x4f 0x7c 0xc9 0x15 0x41 0x23 0xd3 0xfc 0x36 0x37 0x5d 0xee 0x9d 0x21 0x1f 0xd4 0x6d 0xbb 0x10 0xbd 0x9b 0x39 0x79 0xe0 0x5c 0x7a 0xcc 0x19 0x9f 0x22 0xf6 0x7F;

0x80 0x30 0x80 0x01 0x40 0x94 0x6e 0x9c 0x04 0x6b 0x93 0x6d 0x9d 0x17 0xc4 0xb0 0xf6 0x4b 0x1d 0xa8 0x0a 0x26 0x10 0x92 0xf9 0x6b 0x7d 0x12 0x07 0x03 0xb5 0x64 0x73 0x06 0xd3 0x9d 0x06 0x40 0xd8 0xc9 0x79 0xd5 0x3d 0x42 0x8b 0xc7 0x29 0xd4 0x9b 0x38 0x67 0xad 0x76 0xf2 0xe8 0x18 0x90 0x60 0x24 0xb4 0x1a 0x11 0x82 0x38 0xaf 0x4d 0xb7 0xce 0x76 0X7F;

// Step 2. Send data "test". Only one chunk => 0x00 P1 (no more bytes to send), 0x00 P2 (sending data).
0x80 0x30 0x00 0x00 0x04 0x74 0x65 0x73 0x74 0x01;
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
