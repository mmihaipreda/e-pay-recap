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
