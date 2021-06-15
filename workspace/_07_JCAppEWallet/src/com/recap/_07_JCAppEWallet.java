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
