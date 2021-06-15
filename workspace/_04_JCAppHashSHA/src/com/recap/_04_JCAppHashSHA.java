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
