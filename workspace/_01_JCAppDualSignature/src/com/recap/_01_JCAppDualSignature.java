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
