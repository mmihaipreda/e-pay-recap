
package com.recap;

/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */



import javacard.framework.*;

/**
 * Applet class
 * 
 * @author <user>
 */

public class JCAppEWalletRecap extends Applet {
	/* constants declaration */

	// code of CLA byte in the command APDU header
	final static byte Wallet_CLA = (byte) 0x80;

	// codes of INS byte in the command APDU header
	final static byte VERIFY = (byte) 0x20;
	final static byte CREDIT = (byte) 0x30;
	final static byte DEBIT = (byte) 0x40;
	final static byte GET_BALANCE = (byte) 0x50;

	// maximum balance
	//0x7FFF => 0111 1111 1111 1111
	final static short MAX_BALANCE = 0x7FFF;
	// maximum transaction amount
	final static byte MAX_TRANSACTION_AMOUNT = 127;

	// maximum number of incorrect tries before the
	// PIN is blocked
	final static byte PIN_TRY_LIMIT = (byte) 0x03;
	// maximum size PIN
	final static byte MAX_PIN_SIZE = (byte) 0x08;

	// signal that the PIN verification failed
	final static short SW_VERIFICATION_FAILED = 0x6300;
	// signal the the PIN validation is required
	// for a credit or a debit transaction
	final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	// signal invalid transaction amount
	// amount > MAX_TRANSACTION_AMOUNT or amount < 0
	final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

	// signal that the balance exceed the maximum
	final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
	// signal the the balance becomes negative
	final static short SW_NEGATIVE_BALANCE = 0x6A85;

	/* instance variables declaration */
	OwnerPIN pin;
	short balance;
	byte[] pinArray = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

	/**
	 * Installs this applet.
	 * 
	 * @param bArray  the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new JCAppEWalletRecap();
	}

	/**
	 * Only this class's install method should create the applet object.
	 */
	protected JCAppEWalletRecap() {
		// It is good programming practice to allocate
		// all the memory that an applet needs during
		// its lifetime inside the constructor
		this.pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		// The installation parameters contain the PIN
		// initialization value
		this.pin.update(pinArray, (short) (0), (byte) pinArray.length);
		this.balance = (short) 0x00;
		register();
	}

	@Override
	public boolean select() {

		// The applet declines to be selected
		// if the pin is blocked.
		if (this.pin.getTriesRemaining() == 0)
			return false;

		return true;

	}// end of select method

	@Override
	public void deselect() {

		// reset the pin value
		this.pin.reset();

	}

	/**
	 * Processes an incoming APDU.
	 * 
	 * @see APDU
	 * @param apdu the incoming APDU
	 */
	@Override
	public void process(APDU apdu) {

		// APDU object carries a byte array (buffer) to
		// transfer incoming and outgoing APDU header
		// and data bytes between card and CAD

		// At this point, only the first header bytes
		// [CLA, INS, P1, P2, Lc] are available in
		// the APDU buffer.
		// The interface javacard.framework.ISO7816
		// declares constants to denote the offset of
		// these bytes in the APDU buffer

		byte[] buffer = apdu.getBuffer();
		// check SELECT APDU command

		
		/**
		 * if(selectingApplet()) return; 
		 * 
		 * equivalent with 
		 * 
		 * 	buffer[ISO7816.OFFSET_CLA] = (byte) (buffer[ISO7816.OFFSET_CLA] & (byte) 0xFC);
			if ((buffer[ISO7816.OFFSET_CLA] == 0) && (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)))
				return;
		 * 
		 */
		if(selectingApplet()) return;

		// verify the reset of commands have the
		// correct CLA byte, which specifies the
		// command structure
		if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		switch (buffer[ISO7816.OFFSET_INS]) {
		case GET_BALANCE:
			this.getBalance(apdu);
			return;
		case DEBIT:
			this.debit(apdu);
			return;
		case CREDIT:
			this.credit(apdu);
			return;
		case VERIFY:
			this.verify(apdu);
			return;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}

	} // end of process method

	private void credit(APDU apdu) {

		// access authentication
		if (!this.pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

		byte[] buffer = apdu.getBuffer();

		// Lc byte denotes the number of bytes in the
		// data field of the command APDU
		byte numBytes = buffer[ISO7816.OFFSET_LC];

		// indicate that this APDU has incoming data
		// and receive data starting from the offset
		// ISO7816.OFFSET_CDATA following the 5 header
		// bytes.
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// it is an error if the number of data bytes
		// read does not match the number in Lc byte
		if ((numBytes != 1) || (byteRead != 1))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// get the credit amount
		byte creditAmount = buffer[ISO7816.OFFSET_CDATA];

		// check the credit amount
		if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0))
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);

		// check the new balance
		if ((short) (this.balance + creditAmount) > MAX_BALANCE)
			ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);

		// credit the amount
		this.balance = (short) (this.balance + creditAmount);

	} // end of deposit method

	private void debit(APDU apdu) {

		// access authentication
		if (!this.pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

		byte[] buffer = apdu.getBuffer();

		byte numBytes = (byte) (buffer[ISO7816.OFFSET_LC]);

		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		if ((numBytes != 1) || (byteRead != 1))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// get debit amount
		byte debitAmount = buffer[ISO7816.OFFSET_CDATA];

		// check debit amount
		if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0))
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);

		// check the new balance
		if ((short) (this.balance - debitAmount) < (short) 0)
			ISOException.throwIt(SW_NEGATIVE_BALANCE);

		this.balance = (short) (this.balance - debitAmount);

	} // end of debit method

	private void getBalance(APDU apdu) {
		//-> 0x80 0x50 0x00 0x00 0x00 0x02; = Command APDU
		//<- 0x01 0x04 0x90 0x00; = Response APDU
		byte[] buffer = apdu.getBuffer();

		// inform system that the applet has finished
		// processing the command and the system should
		// now prepare to construct a response APDU
		// which contains data field
		// get Le   => apdu.setOutgoing();
		// get number of bytes sent => apdu.setIncomingAndReceive();
		
		short le = apdu.setOutgoing();

		if (le < 2)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// informs the CAD the actual number of bytes
		// returned
		apdu.setOutgoingLength((byte) 2);

		// move the balance data into the APDU buffer
		// starting at the offset 0
		//0x0104 = 260 => 0x01 0x04 = balance
		//					[0] [1] = buffer
		buffer[0] = (byte) (this.balance >> 8); // => 0x00 0x01
		buffer[1] = (byte) (this.balance & 0xFF); // => 0x0104 & 0x00FF => 0x0004 => 0x04

		// send the 2-byte balance at the offset
		// 0 in the apdu buffer
		apdu.sendBytes((short) 0, (short) 2);

	} // end of getBalance method

	private void verify(APDU apdu) {
		//0x80 0x20 0x00 0x00 0x04 0x01 0x02 0x03 0x04 0x00
		byte[] buffer = apdu.getBuffer();
		// retrieve the PIN data for validation.
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// check pin
		// the PIN data is read into the APDU buffer
		// at the offset ISO7816.OFFSET_CDATA
		// the PIN data length = byteRead
		if (this.pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false)
			ISOException.throwIt(SW_VERIFICATION_FAILED);

	} // end of verify method
}

