/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package com.recap.hash;


import javacard.framework.*;
import javacard.security.MessageDigest;
import javacardx.annotations.*;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = { @StringDef(name = "Package", value = "eu.ase.crypto"),
		@StringDef(name = "AppletName", value = "MyApplet") },
		// Insert your strings here
		name = "MyAppletStrings")
public class JCAppHashRecap extends Applet {
	// CLA 		INS 	P1 P2 Lc .... Le
	// 0x80 	0x50 	0x01
	//send 0x80 0x50 0x01 0x00 0x14 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x14;
	//0x80 0x50 0x01 0x00 0x14 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x14;
//	private static final byte CLA_APP = (byte) 0x80;
	private static final byte INS_APP_GENHASH = (byte) 0x50;
	private final MessageDigest sha1;
	private final MessageDigest sha256;
	/**
	 * Installs this applet.
	 * 
	 * @param bArray  the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new JCAppHashRecap();
	}

	/**
	 * Only this class's install method should create the applet object.
	 */
	protected JCAppHashRecap() {
		//arg1:algortihm type
		//arg2: sharable or not
		
		this.sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		this.sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
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
		byte[] buf = apdu.getBuffer();
		if (selectingApplet()) {
			return;
		}
		short len = apdu.setIncomingAndReceive();

		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) INS_APP_GENHASH:
			generateHash(apdu, len);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
	}
	//my file 
	//aaa...abbb..b
	//ccc...cddd..d
	//0x80	0x50	0x81 0x00	0x14 0x61 ... 0x62 ...0x62
	
	
	//CLA	INS 	P1		P2		Lc
	//0x80	0x50	0x01	0x00
	//..................	0x01
	//..............0x81	0x01
	//0x80	0x50	0x02
	//-------------
	// 0x80 0x50 0x81 0x00 0x14 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x00;
	// 0x80 0x50 0x01 0x01 0x14 0x63 0x63 0x63 0x63 0x63 0x63 0x63 0x63 0x63 0x63 0x64 0x64 0x64 0x64 0x64 0x64 0x64 0x64 0x64 0x64 0x14;
	// 0x80 0x50 0x82 0x00 0x14 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x61 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x62 0x00;
	// 0x80 0x50 0x02 0x01 0x14 0x63 0x63 0x63 0x63 0x63 0x63 0x63 0x63 0x63 0x63 0x64 0x64 0x64 0x64 0x64 0x64 0x64 0x64 0x64 0x64 0x20;
	
	
	// JAVA CARD REQUEST INSTRUCTION ANATOMY
	
	//all accesible through ISO7816 interfce
	//CLA	INS		P1		P2		Lc		[CDATA = Lc bytes																																		   ]	Le
	//0x80	0x50	0x81	0x00	0x14	0x61	0x61	0x61	0x61	0x61	0x61	0x61	0x61	0x61	0x61	0x62	0x62	0x62	0x62	0x62	0x62	0x62	0x62	0x62	0x62	0x00;
	
	//RESPONSE INSTRUCTION ANATOMY
	//
	//Optional<DATA OUT>		SW1			SW2	
	
	private void generateHash(APDU apdu, short len) {
		byte[] buffer = apdu.getBuffer();
		//0x80 = 1000 0000
		boolean hasMoreBytes = ((buffer[ISO7816.OFFSET_P1] & 0x80) !=0);
		MessageDigest hash = null;
		short resultLen = 0;
		
		// 0x7F => 0111 1111
		short offset = ISO7816.OFFSET_CDATA;
		switch (buffer[ISO7816.OFFSET_P1] &0x7F) {
		case (byte) 0x01:
			hash = this.sha1;
			resultLen = MessageDigest.LENGTH_SHA;
			break;
		case (byte) 0x02:
			hash = this.sha256;
			resultLen = MessageDigest.LENGTH_SHA_256;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		if(buffer[ISO7816.OFFSET_P2]==0) {
			hash.reset();
		}
		if(hasMoreBytes) {
			hash.update(buffer, offset, len);
		} else {
			hash.doFinal(buffer, offset, len, buffer, (short) 0);
			apdu.setOutgoingAndSend((short) 0, resultLen);
		}

	}
}
