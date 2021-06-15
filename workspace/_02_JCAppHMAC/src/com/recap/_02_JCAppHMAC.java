/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package com.recap;

import javacard.framework.*;
import javacardx.annotations.*;
import static com.recap._02_JCAppHMACStrings.*;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = {
	    @StringDef(name = "Package", value = "com.recap"),
	    @StringDef(name = "AppletName", value = "_02_JCAppHMAC")},
	    // Insert your strings here 
	name = "_02_JCAppHMACStrings")
public class _02_JCAppHMAC extends Applet {

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
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new _02_JCAppHMAC();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected _02_JCAppHMAC() {
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
        //Insert your code here
    }
}
