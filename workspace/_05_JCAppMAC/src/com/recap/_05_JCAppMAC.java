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
