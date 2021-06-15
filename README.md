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
/**
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 *
 */

package com.recap;

import javacard.framework.*;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.annotations.*;
import static com.recap._02_JCAppHMACStrings.*;

/**
 * Applet class
 *
 * @author <user>
 */
@StringPool(value = { @StringDef(name = "Package", value = "com.recap"),
		@StringDef(name = "AppletName", value = "_02_JCAppHMAC") },
		// Insert your strings here
		name = "_02_JCAppHMACStrings")
public class _02_JCAppHMAC extends Applet {

	/**
	 * Installs this applet.
	 *
	 * @param bArray  the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */

	static final byte CLA_HMAC = (byte) 0x80;
	static final byte INS_SET_KEY = (byte) 0x10;
	static final byte INS_SIGN = (byte) 0x20;
	static final byte INS_VERIFY = (byte) 0x30;
	static Signature sign;
	static HMACKey hkey;
	static byte[] verifySignatureBuffer;
	static short offsetVerifySignatureBuffer;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new _02_JCAppHMAC();
	}


	/**
	 * Only this class's install method should create the applet object.
	 */
	protected _02_JCAppHMAC() {
		sign=Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
		verifySignatureBuffer=JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
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

		if(selectingApplet())
			return;
		byte[] buffer = apdu.getBuffer();
		if(buffer[ISO7816.OFFSET_CLA] !=CLA_HMAC){
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		short len = apdu.setIncomingAndReceive();
		switch(buffer[ISO7816.OFFSET_INS]) {
		case INS_SET_KEY:
			this.setKey(apdu, len);
			break;
		case INS_SIGN:
			this.sign(apdu, len);
			break;
		case INS_VERIFY:
			this.verify(apdu, len);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	public void setKey(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();

		// HMAC key size is 64 bytes
		hkey = (HMACKey) KeyBuilder.buildKey(
				KeyBuilder.ALG_TYPE_HMAC,
				JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT,
				(short)(64*8),
				false);
		hkey.setKey(buffer, ISO7816.OFFSET_CDATA, len);
		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, len);
	}

	public void sign(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
		sign.init(hkey, Signature.MODE_SIGN);
		short signatureLen = sign.sign(
				buffer, //inBuff
				ISO7816.OFFSET_CDATA, //offset inBuff
				len, //data length inBuff
				buffer, //output buffer
				(short)0); //offset in output buffer

		apdu.setOutgoingAndSend(
				(short)0,//offset from which
				signatureLen);//how much to send
	}
	public void verify(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
		sign.init(hkey, Signature.MODE_VERIFY);

		boolean hasMoreBytes = (buffer[ISO7816.OFFSET_P1] &(byte)0x80)!=0;
		boolean sentSignatureBytes=(buffer[ISO7816.OFFSET_P2] &(byte)0x01)!=0;

		if(hasMoreBytes) {
			if(sentSignatureBytes) {
				Util.arrayCopy(buffer,
						ISO7816.OFFSET_CDATA,
						verifySignatureBuffer,
						offsetVerifySignatureBuffer,
						len);
				offsetVerifySignatureBuffer+=len;
			}else {
				sign.update(buffer,ISO7816.OFFSET_CDATA, len);
			}
		}else {
			boolean isValid= sign.verify(buffer,
					ISO7816.OFFSET_CDATA,
					len, verifySignatureBuffer,
					(short)0,
					offsetVerifySignatureBuffer);
			offsetVerifySignatureBuffer=0;
			byte responseByte = isValid ?(byte)0x01:(byte)0x00;
			buffer[0]=responseByte;
			apdu.setOutgoingAndSend((short)0, (short)1);
		}

	}
}

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

// Set key
0x80 0x10 0x00 0x00 0x40 0x6f 0xc1 0x05 0x76 0x25 0x7c 0x4c 0xe6 0x3e 0x76 0x4c 0x50 0xa6 0xa0 0x5a 0x25 0xfc 0x77 0x4e 0xde 0x6d 0x1a 0x8a 0xca 0x6c 0x13 0x0e 0xf8 0x82 0xae 0x87 0x6f 0x7b 0x4e 0xf9 0x1e 0x9a 0x4b 0x18 0xfc 0x0e 0x21 0xde 0x43 0x18 0x96 0x3e 0x2e 0x06 0xe8 0xbb 0xe4 0x70 0xb4 0x6f 0xa4 0x37 0x97 0xde 0x0f 0xa6 0xc3 0x7c 0xd8 0x40;

// Sign "test"
0x80 0x20 0x00 0x00 0x04 0x74 0x65 0x73 0x74 0x20;

// Verify signature for "test"

// Step 1: Send signature
0x80 0x30 0x80 0x01 0x20 0x47 0xb5 0x7c 0x5c 0x03 0x2a 0x28 0xa4 0xbb 0xee 0x02 0xed 0xb4 0x4b 0xa8 0x80 0x8f 0x96 0x81 0x20 0x1c 0x16 0x0a 0xdd 0x88 0x9c 0x97 0x89 0x51 0xa5 0x51 0x77 0x7F;

// Step 2: Send data to verify & get response (valid = 0x01, invalid = 0x00)
0x80 0x30 0x00 0x00 0x04 0x74 0x65 0x73 0x74 0x01;
```

---

## 3) AES CBC encryption

#### 3.1 \_03_JCAppAES_CBC.java

```
/**
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 *
 */

package com.recap;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.annotations.*;
import javacardx.crypto.Cipher;

/**
 * Applet class
 *
 * @author <user>
 */
@StringPool(value = { @StringDef(name = "Package", value = "com.recap"),
		@StringDef(name = "AppletName", value = "_03_JCAppAES_CBC") },
		// Insert your strings here
		name = "_03_JCAppAES_CBCStrings")
public class _03_JCAppAES_CBC extends Applet {

	/**
	 * Installs this applet.
	 *
	 * @param bArray  the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */

	static final byte CLA_AES = (byte) 0x80;
	static final byte INS_SET_IV = (byte) 0x10;
	static final byte INS_SET_KEY = (byte) 0x20;
	static final byte INS_ENCRYPT = (byte) 0x30;
	static final byte INS_DECRYPT = (byte) 0x40;
	static Cipher cipher;
	static AESKey key;
	static byte[] iv;
	static short KEY_SIZE_BYTES = KeyBuilder.LENGTH_AES_128 / 8;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new _03_JCAppAES_CBC();
	}

	/**
	 * Only this class's install method should create the applet object.
	 */
	protected _03_JCAppAES_CBC() {
		cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		iv = JCSystem.makeTransientByteArray(KEY_SIZE_BYTES, JCSystem.CLEAR_ON_DESELECT);
		key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
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
		if (buffer[ISO7816.OFFSET_CLA] != CLA_AES)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		short len = apdu.setIncomingAndReceive();

		switch (buffer[ISO7816.OFFSET_INS]) {
		case INS_SET_IV:
			setIV(apdu, len);
			break;
		case INS_SET_KEY:
			setKey(apdu, len);
			break;
		case INS_ENCRYPT:
			encrypt(apdu, len);
			break;
		case INS_DECRYPT:
			decrypt(apdu, len);
			break;
		}
	}

	private void setIV(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, iv, (short) 0, len);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);

	}
	private void setKey(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
		key.setKey(buffer, ISO7816.OFFSET_CDATA);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
	}
	private void encrypt(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
		cipher.init(key, Cipher.MODE_ENCRYPT,iv,(short)0,KEY_SIZE_BYTES);
		short outputLength = cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short)0);
		apdu.setOutgoingAndSend((short)0, outputLength);
	}
	private void decrypt(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
		cipher.init(key, Cipher.MODE_DECRYPT,iv,(short)0,KEY_SIZE_BYTES);
		short plainTextLength = cipher.doFinal(buffer,ISO7816.OFFSET_CDATA,len,buffer,(short)0);
		apdu.setOutgoingAndSend((short)0, plainTextLength);
	}

}

```

#### 3.2 select-com.recap.com.recap.\_03_JCAppAES_CBC.script

```
// Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.

// Applet Selection APDU Script
//
// Package:     _03_JCAppAES_CBC.com.recap
// Package AID: //aid/0102030405/
// Applet:      com.recap._03_JCAppAES_CBC
// Applet AID:  //aid/0102030405/01
//

// Select com.recap._03_JCAppAES_CBC applet
0x00 0xA4 0x04 0x00 0x06 0x01 0x02 0x03 0x04 0x05 0x01 0x7F;
// Set IV
0x80 0x10 0x00 0x00 0x10 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x10;

// Set Key
0x80 0x20 0x00 0x00 0x10 0x07 0x06 0x05 0x04 0x03 0x02 0x01 0x00 0x07 0x06 0x05 0x04 0x03 0x02 0x01 0x00 0x10;

// Encrypt the text "hellohereiamgood"
0x80 0x30 0x00 0x00 0x10 0x68 0x65 0x6c 0x6c 0x6f 0x68 0x65 0x72 0x65 0x69 0x61 0x6d 0x67 0x6f 0x6f 0x64 0x10;

// Decrypt the ciphertext of "hellohereiamgood"
0x80 0x40 0x00 0x00 0x10 0x2e 0x00 0x96 0xfe 0xb9 0x99 0x05 0xed 0x92 0x39 0x20 0x7e 0xe9 0xcd 0x6b 0xa5 0x10;
```

---

## 4) SHA hashing

#### 4.1 \_04_JCAppHashSHA.java

```
/**
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 *
 */


package com.recap;

import javacard.framework.*;
import javacard.security.MessageDigest;
import javacardx.annotations.*;

/**
 * Applet class
 *
 * @author <user>
 */
@StringPool(value = {
	    @StringDef(name = "Package", value = "com.recap"),
	    @StringDef(name = "AppletName", value = "_04_JCAppHashSHA")},
	    // Insert your strings here
	name = "_04_JCAppHashSHAStrings")
public class _04_JCAppHashSHA extends Applet {

    /**
     * Installs this applet.
     *
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
	static final byte CLA_MD5 = (byte)0x80;
	static final byte INS_GEN_HASH = (byte)0x10;
	static MessageDigest messageDigest;
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new _04_JCAppHashSHA();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected _04_JCAppHashSHA() {
    	messageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        register();
    }

    /**
     * Processes an incoming APDU.
     *
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    @Override
    public void process(APDU apdu) {
       if(selectingApplet())
    	   return;

       byte[] buffer = apdu.getBuffer();

       if(buffer[ISO7816.OFFSET_CLA] != CLA_MD5)
    	   ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

       short len = apdu.setIncomingAndReceive();

       switch(buffer[ISO7816.OFFSET_INS]) {
       case INS_GEN_HASH:
    	   generateHash(apdu,len);
    	   break;
       default:
    	   ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
       }
    }

	private void generateHash(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();

		boolean hasMoreBytes = (buffer[ISO7816.OFFSET_P1] & 0x80) != 0;
		boolean shouldReset = (buffer[ISO7816.OFFSET_P2] & 0x01) != 0;

		if(shouldReset) {
			messageDigest.reset();
		}
		if(hasMoreBytes) {
			messageDigest.update(buffer,ISO7816.OFFSET_CDATA,len);
		}else {
			short hashLength = messageDigest.doFinal(buffer,
					ISO7816.OFFSET_CDATA,
					len,
					buffer,
					(short)0);
			apdu.setOutgoingAndSend((short)0, hashLength);
		}

	}
}

```

#### 4.2 select-com.recap.com.recap.\_04_JCAppHashSHA.script

```
// Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.

// Applet Selection APDU Script
//
// Package:     _04_JCAppHashSHA.com.recap
// Package AID: //aid/0102030405/
// Applet:      com.recap._04_JCAppHashSHA
// Applet AID:  //aid/0102030405/01
//

// Select com.recap._04_JCAppHashSHA applet
0x00 0xA4 0x04 0x00 0x06 0x01 0x02 0x03 0x04 0x05 0x01 0x7F;

// Generate hash for lorem
0x80 0x10 0x80 0x01 0x40 0x4c 0x6f 0x72 0x65 0x6d 0x20 0x49 0x70 0x73 0x75 0x6d 0x20 0x69 0x73 0x20 0x73 0x69 0x6d 0x70 0x6c 0x79 0x20 0x64 0x75 0x6d 0x6d 0x79 0x20 0x74 0x65 0x78 0x74 0x20 0x6f 0x66 0x20 0x74 0x68 0x65 0x20 0x70 0x72 0x69 0x6e 0x74 0x69 0x6e 0x67 0x20 0x61 0x6e 0x64 0x20 0x74 0x79 0x70 0x65 0x73 0x65 0x74 0x74 0x69 0x6e 0x67 0x00;
0x80 0x10 0x80 0x00 0x40 0x20 0x69 0x6e 0x64 0x75 0x73 0x74 0x72 0x79 0x2e 0x20 0x4c 0x6f 0x72 0x65 0x6d 0x20 0x49 0x70 0x73 0x75 0x6d 0x20 0x68 0x61 0x73 0x20 0x62 0x65 0x65 0x6e 0x20 0x74 0x68 0x65 0x20 0x69 0x6e 0x64 0x75 0x73 0x74 0x72 0x79 0x27 0x73 0x20 0x73 0x74 0x61 0x6e 0x64 0x61 0x72 0x64 0x20 0x64 0x75 0x6d 0x6d 0x79 0x20 0x74 0x65 0x00;
0x80 0x10 0x80 0x00 0x40 0x78 0x74 0x20 0x65 0x76 0x65 0x72 0x20 0x73 0x69 0x6e 0x63 0x65 0x20 0x74 0x68 0x65 0x20 0x31 0x35 0x30 0x30 0x73 0x2c 0x20 0x77 0x68 0x65 0x6e 0x20 0x61 0x6e 0x20 0x75 0x6e 0x6b 0x6e 0x6f 0x77 0x6e 0x20 0x70 0x72 0x69 0x6e 0x74 0x65 0x72 0x20 0x74 0x6f 0x6f 0x6b 0x20 0x61 0x20 0x67 0x61 0x6c 0x6c 0x65 0x79 0x20 0x6f 0x00;
0x80 0x10 0x80 0x00 0x40 0x66 0x20 0x74 0x79 0x70 0x65 0x20 0x61 0x6e 0x64 0x20 0x73 0x63 0x72 0x61 0x6d 0x62 0x6c 0x65 0x64 0x20 0x69 0x74 0x20 0x74 0x6f 0x20 0x6d 0x61 0x6b 0x65 0x20 0x61 0x20 0x74 0x79 0x70 0x65 0x20 0x73 0x70 0x65 0x63 0x69 0x6d 0x65 0x6e 0x20 0x62 0x6f 0x6f 0x6b 0x2e 0x20 0x49 0x74 0x20 0x68 0x61 0x73 0x20 0x73 0x75 0x72 0x00;
0x80 0x10 0x80 0x00 0x40 0x76 0x69 0x76 0x65 0x64 0x20 0x6e 0x6f 0x74 0x20 0x6f 0x6e 0x6c 0x79 0x20 0x66 0x69 0x76 0x65 0x20 0x63 0x65 0x6e 0x74 0x75 0x72 0x69 0x65 0x73 0x2c 0x20 0x62 0x75 0x74 0x20 0x61 0x6c 0x73 0x6f 0x20 0x74 0x68 0x65 0x20 0x6c 0x65 0x61 0x70 0x20 0x69 0x6e 0x74 0x6f 0x20 0x65 0x6c 0x65 0x63 0x74 0x72 0x6f 0x6e 0x69 0x63 0x00;
0x80 0x10 0x80 0x00 0x40 0x20 0x74 0x79 0x70 0x65 0x73 0x65 0x74 0x74 0x69 0x6e 0x67 0x2c 0x20 0x72 0x65 0x6d 0x61 0x69 0x6e 0x69 0x6e 0x67 0x20 0x65 0x73 0x73 0x65 0x6e 0x74 0x69 0x61 0x6c 0x6c 0x79 0x20 0x75 0x6e 0x63 0x68 0x61 0x6e 0x67 0x65 0x64 0x2e 0x20 0x49 0x74 0x20 0x77 0x61 0x73 0x20 0x70 0x6f 0x70 0x75 0x6c 0x61 0x72 0x69 0x73 0x65 0x00;
0x80 0x10 0x80 0x00 0x40 0x64 0x20 0x69 0x6e 0x20 0x74 0x68 0x65 0x20 0x31 0x39 0x36 0x30 0x73 0x20 0x77 0x69 0x74 0x68 0x20 0x74 0x68 0x65 0x20 0x72 0x65 0x6c 0x65 0x61 0x73 0x65 0x20 0x6f 0x66 0x20 0x4c 0x65 0x74 0x72 0x61 0x73 0x65 0x74 0x20 0x73 0x68 0x65 0x65 0x74 0x73 0x20 0x63 0x6f 0x6e 0x74 0x61 0x69 0x6e 0x69 0x6e 0x67 0x20 0x4c 0x6f 0x00;
0x80 0x10 0x80 0x00 0x40 0x72 0x65 0x6d 0x20 0x49 0x70 0x73 0x75 0x6d 0x20 0x70 0x61 0x73 0x73 0x61 0x67 0x65 0x73 0x2c 0x20 0x61 0x6e 0x64 0x20 0x6d 0x6f 0x72 0x65 0x20 0x72 0x65 0x63 0x65 0x6e 0x74 0x6c 0x79 0x20 0x77 0x69 0x74 0x68 0x20 0x64 0x65 0x73 0x6b 0x74 0x6f 0x70 0x20 0x70 0x75 0x62 0x6c 0x69 0x73 0x68 0x69 0x6e 0x67 0x20 0x73 0x6f 0x00;
0x80 0x10 0x00 0x00 0x3e 0x66 0x74 0x77 0x61 0x72 0x65 0x20 0x6c 0x69 0x6b 0x65 0x20 0x41 0x6c 0x64 0x75 0x73 0x20 0x50 0x61 0x67 0x65 0x4d 0x61 0x6b 0x65 0x72 0x20 0x69 0x6e 0x63 0x6c 0x75 0x64 0x69 0x6e 0x67 0x20 0x76 0x65 0x72 0x73 0x69 0x6f 0x6e 0x73 0x20 0x6f 0x66 0x20 0x4c 0x6f 0x72 0x65 0x6d 0x20 0x49 0x70 0x73 0x75 0x6d 0x2e 0x14;

// Generate hash again - make sure to reset.
0x80 0x10 0x00 0x01 0x04 0x74 0x65 0x73 0x74 0x14;

```

---

## 5) MAC

#### 5.1 \_05_JCAppMAC.java

```
/**
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 *
 */

package com.recap;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.annotations.*;

/**
 * Applet class
 *
 * @author <user>
 */
@StringPool(value = { @StringDef(name = "Package", value = "com.recap"),
		@StringDef(name = "AppletName", value = "_05_JCAppMAC") },
		// Insert your strings here
		name = "_05_JCAppMACStrings")
public class _05_JCAppMAC extends Applet {

	/**
	 * Installs this applet.
	 *
	 * @param bArray  the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */
	static final byte CLA_MAC = (byte) 0x80;
	static final byte INS_SET_IV = (byte) 0x10;
	static final byte INS_SET_KEY = (byte) 0x20;
	static final byte INS_SIGN = (byte) 0x30;
	static final byte INS_VERIFY = (byte) 0x40;

	static Signature sign;
	static AESKey key;
	static byte[] iv;
	static byte[] verifySignatureBuffer;
	static short offsetInVerifySignatureBuffer;
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new _05_JCAppMAC();
	}

	protected _05_JCAppMAC() {
		sign=Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
		key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
		iv = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		verifySignatureBuffer = JCSystem.makeTransientByteArray((short)16,
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

		if (buffer[ISO7816.OFFSET_CLA] != CLA_MAC)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		short len = apdu.setIncomingAndReceive();

		switch (buffer[ISO7816.OFFSET_INS]) {
		case INS_SET_IV:
			setIV(apdu, len);
			break;
		case INS_SET_KEY:
			setKey(apdu, len);
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

	private void setIV(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();

		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, iv, (short) 0, len);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
	}

	private void setKey(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();

		key.setKey(buffer, ISO7816.OFFSET_CDATA);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
	}

	private void sign(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();

        sign.init(key, Signature.MODE_SIGN, iv, (short)0, (short)16);

        short signatureLength = sign.sign(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short)0);

        apdu.setOutgoingAndSend((short)0, signatureLength);
    }

	private void verify(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();

        sign.init(key, Signature.MODE_VERIFY, iv, (short)0, (short)16);

        boolean hasMoreBytes = (buffer[ISO7816.OFFSET_P1] & 0x80) != 0;
        boolean sentSignatureBytes = (buffer[ISO7816.OFFSET_P2] & 0x01) != 0;

        if(hasMoreBytes) {
            if(sentSignatureBytes) {
                Util.arrayCopy(buffer,
                        ISO7816.OFFSET_CDATA,
                        verifySignatureBuffer,
                        offsetInVerifySignatureBuffer,
                        len);
                offsetInVerifySignatureBuffer += len;
            }
            else {
                sign.update(buffer, ISO7816.OFFSET_CDATA, len);
            }
        }
        else {
            boolean isValid = sign.verify(buffer,
                    ISO7816.OFFSET_CDATA,
                    len,
                    verifySignatureBuffer,
                    (short)0,
                    offsetInVerifySignatureBuffer);
            byte resultValue = isValid ? (byte)0x01 : (byte)0x00;
            buffer[0] = resultValue;
            offsetInVerifySignatureBuffer = 0;

            apdu.setOutgoingAndSend((short)0, (short)1);
        }
    }

}

```

#### 5.2 \_05_JCAppMAC.script

```
// Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.

// Applet Selection APDU Script
//
// Package:     _05_JCAppMAC.com.recap
// Package AID: //aid/0102030405/
// Applet:      com.recap._05_JCAppMAC
// Applet AID:  //aid/0102030405/01
//

// Select com.recap._05_JCAppMAC applet
0x00 0xA4 0x04 0x00 0x06 0x01 0x02 0x03 0x04 0x05 0x01 0x7F;
// Set IV.
0x80 0x10 0x00 0x00 0x10 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x10;

// Set Key.
0x80 0x20 0x00 0x00 0x10 0x07 0x06 0x05 0x04 0x03 0x02 0x01 0x00 0x07 0x06 0x05 0x04 0x03 0x02 0x01 0x00 0x10;

// Sign "hellohereiamgood"
0x80 0x30 0x00 0x00 0x10 0x68 0x65 0x6c 0x6c 0x6f 0x68 0x65 0x72 0x65 0x69 0x61 0x6d 0x67 0x6f 0x6f 0x64 0x10;

// Verify signature of "hellohereiamgood"

// Step 1. Send signature
0x80 0x40 0x80 0x01 0x10 0x2e 0x00 0x96 0xfe 0xb9 0x99 0x05 0xed 0x92 0x39 0x20 0x7e 0xe9 0xcd 0x6b 0xa5 0x00;

// Step 2. Send data.
0x80 0x40 0x00 0x00 0x10 0x68 0x65 0x6c 0x6c 0x6f 0x68 0x65 0x72 0x65 0x69 0x61 0x6d 0x67 0x6f 0x6f 0x64 0x01;

```

---

## 6) DES

#### 6.1 \_06_JCAppDES.java

```
/**
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 *
 */

package com.recap;

import javacard.framework.*;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.annotations.*;
import javacardx.crypto.Cipher;

/**
 * Applet class
 *
 * @author <user>
 */
@StringPool(value = { @StringDef(name = "Package", value = "com.recap"),
		@StringDef(name = "AppletName", value = "_06_JCAppDES") },
		// Insert your strings here
		name = "_06_JCAppDESStrings")
public class _06_JCAppDES extends Applet {

	/**
	 * Installs this applet.
	 *
	 * @param bArray  the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */
	static final byte CLA_DES = (byte) 0x80;
	static final byte INS_SET_IV = (byte) 0x10;
	static final byte INS_SET_KEY = (byte) 0x20;
	static final byte INS_ENCRYPT = (byte) 0x30;
	static final byte INS_DECRYPT = (byte) 0x40;

	static Cipher cipher;
	static DESKey key;
	static byte[] iv;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new _06_JCAppDES();
	}

	/**
	 * Only this class's install method should create the applet object.
	 */
	protected _06_JCAppDES() {
		cipher = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
		key = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES, false);
		iv = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
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

		if (buffer[ISO7816.OFFSET_CLA] != CLA_DES)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		short len = apdu.setIncomingAndReceive();

		switch (buffer[ISO7816.OFFSET_INS]) {
		case INS_SET_IV:
			setIV(apdu, len);
			break;
		case INS_SET_KEY:
			setKey(apdu, len);
			break;
		case INS_ENCRYPT:
			encrypt(apdu, len);
			break;
		case INS_DECRYPT:
			decrypt(apdu, len);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void setIV(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();

		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, iv, (short) 0, len);

		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
	}

	private void setKey(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();

		key.setKey(buffer, (short) ISO7816.OFFSET_CDATA);

		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
	}

	private void encrypt(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();

		cipher.init(key, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) 8);

		short cipherTextLength = cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, cipherTextLength);
	}

	private void decrypt(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();

		cipher.init(key, Cipher.MODE_DECRYPT, iv, (short) 0, (short) 8);

		short plaintextLength = cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, plaintextLength);
	}
}

```

#### 6.2 \_06_JCAppDES.script

```
// Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.

// Applet Selection APDU Script
//
// Package:     _06_JCAppDES.com.recap
// Package AID: //aid/0102030405/
// Applet:      com.recap._06_JCAppDES
// Applet AID:  //aid/0102030405/01
//

// Select com.recap._06_JCAppDES applet
0x00 0xA4 0x04 0x00 0x06 0x01 0x02 0x03 0x04 0x05 0x01 0x7F;
// Set IV
0x80 0x10 0x00 0x00 0x08 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08;

// Set Key
0x80 0x20 0x00 0x00 0x08 0x07 0x06 0x05 0x04 0x03 0x02 0x01 0x00 0x08;

// Encrypt the text "hellohereiamgood"
0x80 0x30 0x00 0x00 0x10 0x68 0x65 0x6c 0x6c 0x6f 0x68 0x65 0x72 0x65 0x69 0x61 0x6d 0x67 0x6f 0x6f 0x64 0x10;

// Decrypt the ciphertext of "hellohereiamgood"
0x80 0x40 0x00 0x00 0x18 0xd7 0x3d 0x78 0x98 0x5c 0x1b 0xb9 0x60 0x72 0xb6 0x78 0xaf 0x78 0xb3 0x38 0x92 0xcd 0x36 0x28 0xf0 0xd9 0xff 0x1e 0x45 0x10;


```

---

## 7) E-Wallet

#### 7.1 \_07_JCAppEWallet.java

```
/**
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 *
 */

package com.recap;

import javacard.framework.*;
import javacardx.annotations.*;

/**
 * Applet class
 *
 * @author <user>
 */
@StringPool(value = { @StringDef(name = "Package", value = "com.recap"),
		@StringDef(name = "AppletName", value = "_07_JCAppEWallet") },
		// Insert your strings here
		name = "_07_JCAppEWalletStrings")
public class _07_JCAppEWallet extends Applet {

	/**
	 * Installs this applet.
	 *
	 * @param bArray  the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */

	static final byte CLA_WALLET = (byte) 0x80;
	static final byte INS_VERIFY_PIN = (byte) 0x10;
	static final byte INS_DEPOSIT = (byte) 0x20;
	static final byte INS_WITHDRAW = (byte) 0x30;
	static final byte INS_GET_BALANCE = (byte) 0x40;

	// Custom Status Words
	static final short SW_INCORRECT_PIN = 0x6321;
	static final short SW_PIN_NOT_VALIDATED = 0x6322;
	static final short SW_WRONG_LENGTH = 0x6323;
	static final short SW_TRANSACTION_AMOUNT_INVALID = 0x6324;
	static final short SW_EXCEED_MAXIMUM_BALANCE = 0x6325;
	static final short SW_NEGATIVE_BALANCE = 0x6326;

	static final byte PIN_SIZE_LIMIT = (byte) 0x08;
	static final byte PIN_TRY_LIMIT = (byte) 0x03;
	OwnerPIN pin;
	byte[] correctPin = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

	final static short MAX_BALANCE = 0x7FFF;
	final static byte MAX_TRANSACTION_AMOUNT = 127;
	short balance;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new _07_JCAppEWallet();
	}

	/**
	 * Only this class's install method should create the applet object.
	 */
	protected _07_JCAppEWallet() {
		pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE_LIMIT);

		pin.update(correctPin, (short) 0, (byte) correctPin.length);
		balance = (short) 0x00;
		register();
	}

	@Override
	public boolean select() {
		return pin.getTriesRemaining() != 0;
	}

	@Override
	public void deselect() {
		pin.reset();
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

		if (buffer[ISO7816.OFFSET_CLA] != CLA_WALLET)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		switch (buffer[ISO7816.OFFSET_INS]) {
		case INS_VERIFY_PIN:
			verifyPin(apdu);
			break;
		case INS_DEPOSIT:
			deposit(apdu);
			break;
		case INS_WITHDRAW:
			withdraw(apdu);
			break;
		case INS_GET_BALANCE:
			getBalance(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void verifyPin(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short len = apdu.setIncomingAndReceive();

		if (!pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) len)) {
			ISOException.throwIt(SW_INCORRECT_PIN);
		}
	}

	private void deposit(APDU apdu) {

		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_NOT_VALIDATED);

		byte[] buffer = apdu.getBuffer();

		byte Lc = buffer[ISO7816.OFFSET_LC];
		short len = apdu.setIncomingAndReceive();

		if ((Lc != 1) || (len != 1)) {
			ISOException.throwIt(SW_WRONG_LENGTH);
		}

		byte depositAmount = buffer[ISO7816.OFFSET_CDATA];

		// Check if deposit is within transaction limits.
		if ((depositAmount > MAX_TRANSACTION_AMOUNT) || (depositAmount < 0)) {
			ISOException.throwIt(SW_TRANSACTION_AMOUNT_INVALID);
		}

		// Check if balance + amount fits.
		if ((short) (balance + depositAmount) > MAX_BALANCE) {
			ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
		}

		balance += (short) depositAmount;
	}

	private void withdraw(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_NOT_VALIDATED);

		byte[] buffer = apdu.getBuffer();

		byte Lc = buffer[ISO7816.OFFSET_LC];
		short len = apdu.setIncomingAndReceive();

		if ((Lc != 1) || (len != 1))
			ISOException.throwIt(SW_WRONG_LENGTH);

		byte withdrawAmount = buffer[ISO7816.OFFSET_CDATA];

		if ((withdrawAmount > MAX_TRANSACTION_AMOUNT) || (withdrawAmount < 0))
			ISOException.throwIt(SW_TRANSACTION_AMOUNT_INVALID);

		if ((short) (balance - withdrawAmount) < 0)
			ISOException.throwIt(SW_NEGATIVE_BALANCE);

		balance -= (short) withdrawAmount;
	}

	private void getBalance(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_NOT_VALIDATED);

		byte[] buffer = apdu.getBuffer();

		short Le = apdu.setOutgoing();

		if (Le < 2)
			ISOException.throwIt(SW_WRONG_LENGTH);

		apdu.setOutgoingLength((byte) 2);

		// balance looks like 0x0104 => we now get 0x01.
		buffer[0] = (byte) (balance >> 8);
		// Get the least significant byte value.
		buffer[1] = (byte) (balance & 0xFF);

		apdu.sendBytes((short) 0, (short) 2);
	}
}


```

#### 7.2 \_07_JCAppEWallet.script

```
// Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.

// Applet Selection APDU Script
//
// Package:     _07_JCAppEWallet.com.recap
// Package AID: //aid/0102030405/
// Applet:      com.recap._07_JCAppEWallet
// Applet AID:  //aid/0102030405/01
//

// Select com.recap._07_JCAppEWallet applet
0x00 0xA4 0x04 0x00 0x06 0x01 0x02 0x03 0x04 0x05 0x01 0x7F;

// Verify user pin
0x80 0x10 0x00 0x00 0x05 0x01 0x02 0x03 0x04 0x05 0x7F;

// Get balance
0x80 0x40 0x00 0x00 0x00 0x02;

// Deposit $30
0x80 0x20 0x00 0x00 0x01 0x1e 0x00;

// Get balance
0x80 0x40 0x00 0x00 0x00 0x02;

// Withdraw $25
0x80 0x30 0x00 0x00 0x01 0x19 0x00;

// Get balance
0x80 0x40 0x00 0x00 0x00 0x02;


```

---
