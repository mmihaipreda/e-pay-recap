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
