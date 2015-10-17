/*
 * Copyright (c) 2010-2015, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.zwave.internal.protocol.commandclass;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.AbstractQueue;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.openhab.binding.zwave.internal.protocol.SerialMessage;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessageClass;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessagePriority;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessageType;
import org.openhab.binding.zwave.internal.protocol.ZWaveController;
import org.openhab.binding.zwave.internal.protocol.ZWaveEndpoint;
import org.openhab.binding.zwave.internal.protocol.ZWaveNode;
import org.openhab.binding.zwave.internal.protocol.event.ZWaveInclusionEvent;
import org.openhab.binding.zwave.internal.protocol.event.ZWaveInclusionEvent.Type;
import org.openhab.binding.zwave.internal.protocol.serialmessage.ApplicationCommandMessageClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamOmitField;

/**
 * Handles the Security command class.
 *
 * @author Dave Badia
 * @since 1.7.0
 */
@XStreamAlias("securityCommandClass")
public class ZWaveSecurityCommandClass extends ZWaveCommandClass implements
		ZWaveCommandClassInitialization {
	private static final Logger logger = LoggerFactory.getLogger(ZWaveSecurityCommandClass.class);
	/**
	 * How long the device has to respond to nonce requests.  Per spec, min=3, recommended=10, max=20
	 */
	private static final long NONCE_MAX_MILLIS = TimeUnit.SECONDS.toMillis(10);
	/**
	 * It's a security best practice to periodically re-seed our random number
	 * generator
	 * http://www.cigital.com/justice-league-blog/2009/08/14/proper-use-of-javas-securerandom/
	 */
	private static final long SECURE_RANDOM_RESEED_INTERVAL_MILLIS = TimeUnit.DAYS.toMillis(1);

	/**
	 * Security messages require multiple rounds of encryption so we
	 * need to allow extra time before we give up on not getting
	 * a response
	 */
	private static final int WAIT_TIME_MILLIS = 20000;

	/**
	 * Per the z-wave spec, this is the AES key used to derive {@link #encryptKey} from {@link #networkKey}
	 */
	private static final byte[] DERIVE_ENCRYPT_KEY = { (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
			(byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
			(byte) 0xAA, (byte) 0xAA, (byte) 0xAA };
	/**
	 * Per the z-wave spec, this is the AES key used to derive {@link #authKey} from {@link #networkKey}
	 */
	private static final byte[] DERIVE_AUTH_KEY = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
			0x55, 0x55, 0x55, 0x55, 0x55 };
	private static final String AES = "AES";
	private static final int MAC_LENGTH = 8;
	private static final int IV_LENGTH = 16;
	private static final int HALF_OF_IV = IV_LENGTH / 2;
	/**
	 * Marks the end of the list of supported command classes. The remaining classes are those that can be controlled by
	 * the device. These classes are created without values. Messages received cause notification events instead.
	 */
	public static final byte COMMAND_CLASS_MARK = (byte) 0xef;

	/**
	 * Request which commands the device supports using
	 * security encapsulation (encryption)
	 */
	static final byte SECURITY_COMMANDS_SUPPORTED_GET = 0x02;
	/**
	 * Response from the device which indicates which commands
	 * the device supports using security encapsulation (encryption)
	 */
	static final byte SECURITY_COMMANDS_SUPPORTED_REPORT = 0x03;
	/**
	 * Request which security initialization schemes the
	 * device supports
	 */
	static final byte SECURITY_SCHEME_GET = 0x04;
	/**
	 * Response from the device of  which security initialization
	 * schemes the device supports
	 */
	static final byte SECURITY_SCHEME_REPORT = 0x05;
	/**
	 * The controller is sending the device the network key to
	 * be used for all secure transmissions
	 */
	static final byte SECURITY_NETWORK_KEY_SET = 0x06;
	/**
	 * Response from the device after getting SECURITY_NETWORK_KEY_SET
	 * that was encapsulated using the new key
	 */
	static final byte SECURITY_NETWORK_KEY_VERIFY = 0x07;
	/**
	 * Not supported since we are always the master
	 */
	private static final byte SECURITY_SCHEME_INHERIT = 0x08;
	/**
	 * Request to generate a nonce to be used in message encapsulation
	 */
	static final byte SECURITY_NONCE_GET = 0x40;
	/**
	 * Response with the generated nonce to be used in message encapsulation
	 */
	private static final byte SECURITY_NONCE_REPORT = (byte) 0x80;
	/**
	 * Indicates this message has been encapsulated and must be decrypted
	 * to reveal the actual message
	 * public so {@link ApplicationCommandMessageClass} can check for this and invoke
	 * {@link #decryptMessage(byte[], int)} as needed
	 */
	public static final byte SECURITY_MESSAGE_ENCAP = (byte) 0x81;
	/**
	 * Indicates this message has been encapsulated and must be decrypted
	 * to reveal the actual message and that there are more messages to
	 * send so another nonce is needed.
	 * public so {@link ApplicationCommandMessageClass} can check for this and invoke
	 * {@link #decryptMessage(byte[], int)} as needed
	 */
	public static final byte SECURITY_MESSAGE_ENCAP_NONCE_GET = (byte) 0xc1;

	private static final Map<Byte, String> COMMAND_LOOKUP_TABLE = new ConcurrentHashMap<Byte, String>();

	/**
	 * Per the z-wave spec, the this scheme is used prior to any keys being negotiated
	 */
	private static final byte SECURITY_SCHEME_ZERO = 0x00;

	private static final List<Byte> REQUIRED_ENCAPSULATION_LIST =
			Arrays.asList(new Byte[]{
					SECURITY_NETWORK_KEY_SET,
					SECURITY_NETWORK_KEY_VERIFY,
					SECURITY_SCHEME_INHERIT,
					SECURITY_COMMANDS_SUPPORTED_GET,
					SECURITY_COMMANDS_SUPPORTED_REPORT});

	/**
	 * Should be set to true
	 *
	 * The code from which this was based included numerous bad security practices (hardcoded IVs, seeding of PRNG
	 * with timestamp).
	 *
	 * It is unknown as to whether that logic was necessary to work around device defects or if it was just by mistake.
	 *
	 * Setting this to false will use the bad security practices from the original code. true will use accepted security
	 * best practices
	 *
	 * Package-protected visible for test case use
	 */
	static boolean USE_SECURE_CRYPTO_PRACTICES = true;

	/**
	 * Should be set to true to ensure all incoming security encapsulated messages adhere to
	 * zwave security mac standards
	 *
	 * Package-protected visible for test case use
	 */
	static boolean DROP_PACKETS_ON_MAC_FAILURE = true;

	/**
	 * Should be set to true unless we find a good reason not to
	 *
	 * OZW code comments say that {@link #SECURITY_MESSAGE_ENCAP_NONCE_GET}
	 * doesn't work so keep a flag to enable/disable.
	 *
	 * Package-protected visible for test case use
	 */
	static boolean USE_SECURITY_MESSAGE_ENCAP_NONCE_GET = true;

	/**
	 * Should be set to false unless we find a good reason not to
	 *
	 * OZW code sets different transmit option flags for some security
	 * messages.
	 *
	 * Package-protected visible for test case use
	 */
	static boolean OVERRIDE_DEFAULT_TRANSMIT_OPTIONS = false;

	/**
	 * Security messages are time sensitive so mark them as high priority
	 */
	private static final SerialMessagePriority SECURITY_MESSAGE_PRIORITY = SerialMessagePriority.High;
	/**
	 * Header is made up of 10 bytes:
	 * command class byte
	 * message type byte
	 * 8 bytes for the device's nonce
	 */
	private static final int ENCAPSULATED_HEADER_LENGTH = 10;
	/**
	 * Footer consists of the nonce ID (1 byte) and the MAC (8 bytes)
	 */
	private static final int ENCAPSULATED_FOOTER_LENGTH = 9;

	@XStreamOmitField
	private NonceTable nonceTable = new NonceTable();
	/**
	 * Timer to track time elapsed between sending {@link #SECURITY_NONCE_GET} and
	 * receiving {@link #SECURITY_NONCE_REPORT}.  Per the z-wave spec, if too
	 * much time elapses we should request a new nonce
	 */
	@XStreamOmitField
	private NonceTimer requestNonceTimer = new NonceTimer();
	/**
	 * Queue of {@link ZWaveSecurityPayloadFrame} that are waiting for nonces
	 * so they can be encapsulated and set
	 */
	@XStreamOmitField
	private AbstractQueue<ZWaveSecurityPayloadFrame> payloadEncapsulationQueue = new ConcurrentLinkedQueue<ZWaveSecurityPayloadFrame>();
	@XStreamOmitField
	private AtomicBoolean waitingForNonce = new AtomicBoolean(false);

	/**
	 * The network key as configured in the openhab.cfg -> zwave:networkey
	 */
	@XStreamOmitField
	private static SecretKey realNetworkKey;
	/**
	 * The error that occurred when trying to load the encryption key from openhab.cfg -> zwave:networkey
	 * Will be null if the load succeeded
	 */
	@XStreamOmitField
	private static Exception keyException;

	/**
	 * The network key currently in use.  My be {@link #realNetworkKey} or a scheme network key
	 */
	@XStreamOmitField
	private SecretKey networkKey;
	/**
	 * The encryption key currently in use which is derived from {@link #networkKey}
	 */
	@XStreamOmitField
	private SecretKey encryptKey;
	/**
	 * The auth key currently in use which is derived from {@link #networkKey}
	 */
	@XStreamOmitField
	private SecretKey authKey;
	/**
	 * Only non-null when we are including a new node
	 */
	@XStreamOmitField
	private volatile ZWaveSecureInclusionStateTracker inclusionStateTracker = null;

	/**
	 * Flag so we understand that the secure pairing process was completed
	 * This is set after we receive the {@value #SECURITY_NETWORK_KEY_VERIFY} message
	 */
	private boolean securePairingComplete = false;

	/**
	 * Timer that tracks how long we should wait for a response
	 */
	@XStreamOmitField
	private long waitForReplyTimeout = Long.MAX_VALUE;

	static {
		// Initialize the COMMAND_LOOKUP_TABLE
		COMMAND_LOOKUP_TABLE.put(Byte.valueOf(SECURITY_COMMANDS_SUPPORTED_GET), "SECURITY_COMMANDS_SUPPORTED_GET");
		COMMAND_LOOKUP_TABLE.put(Byte.valueOf(SECURITY_COMMANDS_SUPPORTED_REPORT), "SECURITY_COMMANDS_SUPPORTED_REPORT");
		COMMAND_LOOKUP_TABLE.put(Byte.valueOf(SECURITY_SCHEME_GET), "SECURITY_SCHEME_GET");
		COMMAND_LOOKUP_TABLE.put(Byte.valueOf(SECURITY_SCHEME_REPORT), "SECURITY_SCHEME_REPORT");
		COMMAND_LOOKUP_TABLE.put(Byte.valueOf(SECURITY_NETWORK_KEY_SET), "SECURITY_NETWORK_KEY_SET");
		COMMAND_LOOKUP_TABLE.put(Byte.valueOf(SECURITY_NETWORK_KEY_VERIFY), "SECURITY_NETWORK_KEY_VERIFY");
		COMMAND_LOOKUP_TABLE.put(Byte.valueOf(SECURITY_SCHEME_INHERIT), "SECURITY_SCHEME_INHERIT");
		COMMAND_LOOKUP_TABLE.put(Byte.valueOf(SECURITY_NONCE_GET), "SECURITY_NONCE_GET");
		COMMAND_LOOKUP_TABLE.put(Byte.valueOf(SECURITY_NONCE_REPORT), "SECURITY_NONCE_REPORT");
		COMMAND_LOOKUP_TABLE.put(Byte.valueOf(SECURITY_MESSAGE_ENCAP), "SECURITY_MESSAGE_ENCAP");
		COMMAND_LOOKUP_TABLE.put(Byte.valueOf(SECURITY_MESSAGE_ENCAP_NONCE_GET), "SECURITY_MESSAGE_ENCAP_NONCE_GET");
		for(Map.Entry<Byte, String> entry : COMMAND_LOOKUP_TABLE.entrySet()) {
			logger.debug(String.format("COMMAND_LOOKUP_TABLE 0x%02X %s", entry.getKey(), entry.getValue()));
		}
	}

	/**
	 * Creates a new instance of the ZWaveThermostatFanModeCommandClass class.
	 *
	 * @param node
	 *            the node this command class belongs to
	 * @param controller
	 *            the controller to use
	 * @param endpoint
	 *            the endpoint this Command class belongs to
	 */
	public ZWaveSecurityCommandClass(ZWaveNode node, ZWaveController controller, ZWaveEndpoint endpoint) {
		super(node, controller, endpoint);
		if(!checkRealNetworkKeyLoaded()) {
			throw new IllegalStateException("NODE "+getNode().getNodeId()+": node wants to use security but key is not set");
		}
		setupNetworkKey(false);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public CommandClass getCommandClass() {
		return CommandClass.SECURITY;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getMaxVersion() {
		return 1;
	}

	/**
	 * The Security command class is unique in that only some commands require encryption
	 * (for all others, the security encapsulation requirement applies to the entire command class.)
	 */
	public static boolean doesCommandsRequireSecurityEncapsulation(Byte commandByte) {
		return REQUIRED_ENCAPSULATION_LIST.contains(commandByte);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void handleApplicationCommandRequest(SerialMessage serialMessage, int offset, int endpoint) {
		logger.trace("handleApplicationCommandRequest called from Thread "+Thread.currentThread().getName());
		byte command = (byte) serialMessage.getMessagePayloadByte(offset);
		if(logger.isDebugEnabled()) {
			logger.debug(String.format("NODE %s: Received Security Message 0x%02X %s ", this.getNode().getNodeId(),
					command, commandToString(command)));
		}
		traceHex("payload bytes for incoming security message", serialMessage.getMessagePayload());

		if(inclusionStateTracker != null && !inclusionStateTracker.verifyAndAdvanceState(command)) {
			// bad order, abort
			return;
		}

		switch (command) {

		case SECURITY_COMMANDS_SUPPORTED_REPORT:
			byte[] messagePayload = serialMessage.getMessagePayload();
			int ourOffset = offset + 1;
			int size = messagePayload.length - ourOffset;
			byte[] secureClassBytes = new byte[size];
			System.arraycopy(messagePayload, ourOffset, secureClassBytes, 0, size);
			traceHex("Supported Security Classes", secureClassBytes);
			getNode().setSecuredClasses(secureClassBytes);
			// This can be received during device inclusion or outside of it
			if(inclusionStateTracker != null) {
				// We're done with all of our NodeStage#SECURITY_REPORT stuff, set inclusionStateTracker to null
				inclusionStateTracker = null;
			}
			return;

		case SECURITY_SCHEME_REPORT:
			// Should be received during inclusion only
			if(!wasThisNodeJustIncluded() || inclusionStateTracker == null) {
				logger.error("NODE {}: Received SECURITY_SCHEME_REPORT but we are not in inclusion mode! {}", serialMessage);
				return;
			}
			int schemes = serialMessage.getMessagePayloadByte(offset + 1);
			logger.debug("NODE {}: Received Security Scheme Report: ", this.getNode().getNodeId(), schemes);
			if (schemes == SECURITY_SCHEME_ZERO) {
				// Since we've agreed on a scheme for which to exchange our key, we now send our NetworkKey to the device
				logger.debug("NODE {}: Security scheme agreed.", this.getNode().getNodeId());
				// create the NetworkKey Packet
				SerialMessage networkKeyMessage = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
						SerialMessageType.Request, SerialMessageClass.SendData, SECURITY_MESSAGE_PRIORITY);
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				baos.write((byte) this.getNode().getNodeId());
				baos.write(18);
				baos.write((byte) getCommandClass().getKey());
				baos.write(SECURITY_NETWORK_KEY_SET);
				try {
					baos.write(realNetworkKey.getEncoded());
					networkKeyMessage.setMessagePayload(baos.toByteArray());
					// We can't set SECURITY_NETWORK_KEY_SET in inclusionStateTracker because we need to do a
					// NONCE_GET before sending.  So put this in our encrypt send queue
					// and give inclusionStateTracker/ZWaveNodeStageAdvancer the NONCE_GET
					waitingForNonce.set(true); // true since we will build our own NONCE_GET
					queueMessageForEncapsulation(networkKeyMessage);
					if(!inclusionStateTracker.verifyAndAdvanceState(SECURITY_NETWORK_KEY_SET)) {
						// incorrect order
						return;
					}
					inclusionStateTracker.setNextRequest(buildNonceGet()); // Let ZWaveNodeStageAdvancer come get it
				} catch (IOException e) {
					logger.error("NODE {}: IOException trying to write SECURITY_NETWORK_KEY_SET, aborted", e);
				}
			} else {
				// No common security scheme. The device should continue as an unsecured node. but some Command Classes
				// might not be present...
				inclusionStateTracker.setErrorState("TODO: Security scheme "+schemes+" is not supported");
				logger.error("NODE {}: No common security scheme.  The device will continue as an unsecured node.  " +
						"Scheme requested was {}", this.getNode().getNodeId(), schemes);
			}
			return;

		case SECURITY_NETWORK_KEY_SET:
			// we shouldn't get a NetworkKeySet from a node if we are the controller as we send it out to the Devices
			logger.info("NODE {}: Received SECURITY_NETWORK_KEY_SET from node but we shouldn't have gotten it.", this
					.getNode().getNodeId());
			return;

		case SECURITY_NETWORK_KEY_VERIFY:
			// Should be received during inclusion only
			if(!wasThisNodeJustIncluded() || inclusionStateTracker == null) {
				logger.error("NODE {}: Received SECURITY_NETWORK_KEY_VERIFY but we are not in inclusion mode! {}", serialMessage);
				return;
			}
			// Since we got here, it means we decrypted a packet using the key we sent in
			// the SECURITY_NETWORK_KEY_SET message and the new key is in use by both sides.
			// Next step is to send SECURITY_COMMANDS_SUPPORTED_GET
			securePairingComplete = true;
			SerialMessage supportedGetMessage = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
					SerialMessageType.Request, SerialMessageClass.SendData, SECURITY_MESSAGE_PRIORITY);
			byte[] payload = {
					(byte) this.getNode().getNodeId(),
					2,
					(byte) getCommandClass().getKey(),
					SECURITY_COMMANDS_SUPPORTED_GET,
			};
			supportedGetMessage.setMessagePayload(payload);
			// We can't set SECURITY_COMMANDS_SUPPORTED_GET in inclusionStateTracker because we need to do a
			// NONCE_GET before sending.  So put this in our encrypt send queue
			// and give inclusionStateTracker/ZWaveNodeStageAdvancer the NONCE_GET
			waitingForNonce.set(true); // true since we will build our own NONCE_GET
			queueMessageForEncapsulation(supportedGetMessage);
			inclusionStateTracker.verifyAndAdvanceState(SECURITY_COMMANDS_SUPPORTED_GET);
			inclusionStateTracker.setNextRequest(buildNonceGet()); // Let ZWaveNodeStageAdvancer come get it
			return;

		case SECURITY_SCHEME_INHERIT:
			//  only used in a controller replication type environment.
			logger.info("NODE {}: Received SECURITY_SCHEME_INHERIT from node but it's not supported: {}", this
					.getNode().getNodeId(), serialMessage);
			return;

		case SECURITY_NONCE_GET:
			// the Device wants to send us a Encrypted Packet, and thus requesting for our latest NONCE
			sendNonceReport();
			return;

		case SECURITY_NONCE_REPORT:
			// we received a NONCE from a device, so assume that there is something in a queue to send out
			// Nonce is messageBuf without the first offset +1 bytes
			byte[] messageBuf = serialMessage.getMessagePayload();
			int startAt = offset + 1;
			int copyCount = messageBuf.length - startAt;
			byte[] nonce = new byte[copyCount];
			System.arraycopy(messageBuf, startAt, nonce, 0, copyCount);
			waitingForNonce.set(false);
			sendNextMessageWithNonce(nonce);
			return;

		case SECURITY_MESSAGE_ENCAP:
			// SECURITY_MESSAGE_ENCAP should be caught and handled in {@link ApplicationCommandMessageClass}
			logger.warn("NODE {}: Received SECURITY_MESSAGE_ENCAP in ZWaveSecurityCommandClass which should not happen: {}.",
					this.getNode().getNodeId(), serialMessage);
			return;

		case SECURITY_MESSAGE_ENCAP_NONCE_GET:
			// SECURITY_MESSAGE_ENCAP_NONCE_GET should be caught and handled in {@link ApplicationCommandMessageClass}
			logger.warn("NODE {}: Received SECURITY_MESSAGE_ENCAP_NONCE_GET in ZWaveSecurityCommandClass which should not happen: {}.",
					this.getNode().getNodeId(), serialMessage);
			return;

		default:
			logger.warn(String.format("NODE %s: Unsupported Command 0x%02X for command class %s (0x%02X) for message %s.",
					this.getNode().getNodeId(), command, this.getCommandClass().getLabel(),
					this.getCommandClass().getKey(), serialMessage));
		}
	}

	/**
	 * Decrypts a security encapsulated message from the Z-Wave network.  Ideally this would return
	 * a {@link SerialMessage} but we don't have enough data to do so.  So we just return the
	 * decrypted payload bytes
	 * @param offset the offset at which the command byte exists
	 * @param endpoint
	 * @param messagePayload
	 * @return the decrypted payload bytes.  0=command class, 1=command, 2+=payload
	 */
	public byte[] decryptMessage(byte[] data, int offset) {
		if(!checkRealNetworkKeyLoaded()) {
			return null;
		}
		traceHex("in decryptMessage starting at offset, buffer is", data, offset);
		ByteArrayInputStream bais = new ByteArrayInputStream(data);
		// check for minimum size here so we can ignore the return value of bais.read() below
		int minimumSize = offset + ENCAPSULATED_HEADER_LENGTH + ENCAPSULATED_FOOTER_LENGTH;
		if(data.length < minimumSize) {
			logger.error("NODE {}: Dropping security encapsulated packet which is too small:  min={}, actual={}",
					this.getNode().getNodeId(), minimumSize, data.length);
			return null;
		}
		try {
			// advance to the command byte
			bais.read(new byte[offset]);
			byte command = (byte) bais.read();
			byte[] initializationVector = new byte[IV_LENGTH];
			// the next 8 bytes of packet are the nonce generated by the device for the IV
			bais.read(initializationVector, 0, HALF_OF_IV);
			traceHex("device nonce", initializationVector, 0, HALF_OF_IV);
			int ciphertextSize = data.length - offset - ENCAPSULATED_HEADER_LENGTH - ENCAPSULATED_FOOTER_LENGTH + 1;
			// Next are the ciphertext bytes
			byte[] ciphertextBytes = new byte[ciphertextSize];
			bais.read(ciphertextBytes);
			logger.info("NODE {}: Encrypted Packet Sizes: total={}, encrypted={}", this.getNode().getNodeId(), data.length,
					ciphertextSize);
			traceHex("ciphertextBytes", ciphertextBytes);
			// Get the nonce id so we can populate the 2nd half of the IV
			byte nonceId = (byte) bais.read();
			if (USE_SECURE_CRYPTO_PRACTICES) {
				Nonce nonce = nonceTable.getNonceById(nonceId);
				if(nonce == null) {
					logger.error("NODE {}: Could not find nonce (probably expired) for id={} in table={}",
							this.getNode().getNodeId(), nonceId, nonceTable.table);
					return null;
				}
				System.arraycopy(nonce.getNonceBytes(), 0, initializationVector, HALF_OF_IV, HALF_OF_IV);
			} else {
				byte[] insecureNonce = new byte[HALF_OF_IV];
				Arrays.fill(insecureNonce, (byte) 0xAA);
				System.arraycopy(insecureNonce, 0, initializationVector, HALF_OF_IV, HALF_OF_IV);
			}
			traceHex("IV", initializationVector);
			byte[] macFromPacket = new byte[MAC_LENGTH];
			bais.read(macFromPacket);
			Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, encryptKey, new IvParameterSpec(initializationVector));
			byte[] plaintextBytes = cipher.doFinal(ciphertextBytes);
			traceHex("plaintextBytes", plaintextBytes);

			byte driverNodeId = (byte) this.getController().getOwnNodeId();
			byte[] mac = generateMAC(command, ciphertextBytes, (byte) this.getNode().getNodeId(), driverNodeId,
					initializationVector);
			if (Arrays.equals(mac, macFromPacket)) {
				logger.debug("NODE {}: MAC Authentication of packet verified OK", this.getNode().getNodeId());
			} else {
				logger.error("NODE {}: MAC Authentication of packet failed. dropping", this.getNode().getNodeId());
				traceHex("full packet", data);
				traceHex("package mac", macFromPacket);
				traceHex("our mac", mac);
				if (payloadEncapsulationQueue.size() > 0) {
					requestNonce(); // handle the next one
				}
				if (DROP_PACKETS_ON_MAC_FAILURE) {
					return null;
				} else {
					logger.error("NODE {}: Just kidding, ignored failed MAC Authentication of packet", this.getNode()
							.getNodeId());
				}
			}
			byte sequenceDataByte = plaintextBytes[0];
			if(sequenceDataByte != ZWaveSecurityPayloadFrame.SEQUENCE_BYTE_FOR_SINGLE_FRAME_MESSAGE) {
				// This is a multi frame message which is not yet supported
				logger.error("NODE {}: Received multi frmae message which is not supported.  Please post this to the OpenHab" +
						"mailing list so it can be fixed!  bytes=", this.getNode().getNodeId(), SerialMessage.bb2hex(plaintextBytes));
				return null;
			}
			// so we know if we got something that's not supported
			logger.debug("NODE {}: decrypted bytes {}", getNode().getNodeId(), SerialMessage.bb2hex(plaintextBytes));
			return plaintextBytes;
		} catch (Exception e) {
			logger.error("Error decrypting packet", e);
			return null;
		}
	}

	/**
	 * Generate a new nonce, then build a SECURITY_NONCE_REPORT and send it
	 */
	public void sendNonceReport() {
		byte[] newNonce = nonceTable.generateNewNonce().getNonceBytes();
		if (!USE_SECURE_CRYPTO_PRACTICES) {
			newNonce = new byte[HALF_OF_IV];
			Arrays.fill(newNonce, (byte) 0xAA);
		}

		SerialMessage message = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
				SerialMessageType.Request, SerialMessageClass.SendData, SECURITY_MESSAGE_PRIORITY);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write((byte) this.getNode().getNodeId());
		baos.write((byte) 10);
		baos.write((byte) getCommandClass().getKey());
		baos.write(SECURITY_NONCE_REPORT);
		try {
			baos.write(newNonce);
			message.setMessagePayload(baos.toByteArray());
			if(OVERRIDE_DEFAULT_TRANSMIT_OPTIONS) {
				logger.debug("NODE {}: Using custom transmit options", getNode().getNodeId());
				message.setTransmitOptions(ZWaveController.TRANSMIT_OPTION_ACK | ZWaveController.TRANSMIT_OPTION_AUTO_ROUTE);
			}
		} catch (IOException e) {
			logger.error("NODE {}: Error during Security sendNonceReport.", e);
		}
		// This can be done during device inclusion or outside of it
		if(inclusionStateTracker == null) {
			this.getController().sendData(message);
		} else { // inclusionMode = true
			// Hand this response to the inclusionStateTracker
			inclusionStateTracker.setNextRequest(message);
		}
	}

	/**
	 * Queues the given message for security encapsulation and transmission.
	 *
	 * Note that, per the z-wave spec, we don't just encrypt the message and send it. We need to first request a nonce
	 * from the node, wait for that response, then encrypt and send. Therefore this message will be split into one or
	 * more security frames, placed into a queue until the next nonce is received. Only then will it be encrypted and sent.
	 *
	 * @param message
	 *            the unencrypted message to be transmitted
	 */
	public void queueMessageForEncapsulation(SerialMessage serialMessage) {
		if (serialMessage.getMessageBuffer().length < 7) {
			logger.error("NODE {}: Message too short for encapsulation, dropping message {}", this.getController()
					.getNode(serialMessage.getMessageNode()).getNodeId(), serialMessage);
			return;
		}

		if (serialMessage.getMessageClass() != SerialMessageClass.SendData) {
			logger.error(String.format("Invalid message class %s (0x%02X) for sendData for message %s", serialMessage
					.getMessageClass().getLabel(), serialMessage.getMessageClass().getKey(), serialMessage.toString()));
		}

		logger.info("NODE {}: Adding to security encapsulation queue (waiting for nonce reply) {} {}",
				this.getNode().getNodeId(), SerialMessage.bb2hex(serialMessage.getMessageBuffer()),
				serialMessage);

		// Start with command class byte, so strip off node and length
		int copyLength = serialMessage.getMessagePayload().length - 2;
		byte[] payloadBuffer = new byte[copyLength];
		System.arraycopy(serialMessage.getMessagePayload(), 2, payloadBuffer, 0, copyLength);

		List<ZWaveSecurityPayloadFrame> securityPayloadFrameList = ZWaveSecurityPayloadFrame.convertToSecurityPayload(getNode(), payloadBuffer, serialMessage.toString());
		queuePayloadForEncapsulationAndTransmission(securityPayloadFrameList);
	}

	/**
	 * Queue a {@link ZWaveSecurityPayloadFrame} to be security encapsulated (encrypted and MACed)
	 * on receipt of a nonce value from the remote node.
	 *
	 * @param securityPayloadList
	 *            the payload(s) to be encapsulated (encrypted)
	 */
	private void queuePayloadForEncapsulationAndTransmission(List<ZWaveSecurityPayloadFrame> securityPayloadList) {
		// Due to XStreamOmitField, payloadEncapsulationQueue and waitingForNonce can be null
		if(payloadEncapsulationQueue == null) {
			payloadEncapsulationQueue = new ConcurrentLinkedQueue<ZWaveSecurityPayloadFrame>();
		}
		if(waitingForNonce == null) {
			waitingForNonce = new AtomicBoolean(false);
		}
		// Now we can get to our logic
		if(!payloadEncapsulationQueue.isEmpty()) {
			logger.warn("Removing old items from payloadEncapsulationQueue: "+payloadEncapsulationQueue);
			payloadEncapsulationQueue.clear();
		}
		payloadEncapsulationQueue.addAll(securityPayloadList);
		logger.debug("NODE {}: queuePayloadForEncapsulationAndTransmission waitingForNonce={}", this.getNode()
				.getNodeId(),waitingForNonce);

		if (!waitingForNonce.get()) {
			// Request a nonce from the node. Its arrival
			// will trigger the encapsulation and sending of the first payload in the queue
			requestNonce();
		}
	}

	/**
	 * Gets the next message from {@link #payloadEncapsulationQueue}, encapsulates (encrypts and MACs) it, then transmits
	 *
	 * @param deviceNonce
	 *            the nonce from the device which is used as the 2nd half of the IV
	 */
	private void sendNextMessageWithNonce(byte deviceNonce[]) {
		if(!checkRealNetworkKeyLoaded()) {
			return;
		}
		if(encryptKey == null) {
			// when loaded from xml, encrypt key will be null so we load it here
			setupNetworkKey(false);
		}
		// Due to XStreamOmitField, requestNonceTimer and nonceTable can be null
		if(requestNonceTimer == null) {
			requestNonceTimer = new NonceTimer();
		}
		if(nonceTable == null) {
			nonceTable = new NonceTable();
		}
		if (requestNonceTimer.isExpired()) {
			// The nonce was not received within the alloted time of us sending the nonce request. Send it again
			logger.warn("NODE {}: nonce was not received within 10 seconds, resending request.", this.getNode()
					.getNodeId());
			requestNonce();
			return;
		}

		traceHex("device nonce for next message send", deviceNonce);
		// Fetch the next payload from the queue and encapsulate it
		ZWaveSecurityPayloadFrame securityPayload = payloadEncapsulationQueue.poll();
		if (securityPayload == null) {
			logger.trace("NODE {}: payloadQueue was empty, returning.", this.getNode().getNodeId());
			return;
		}

		// Encapsulate the message fragment
		logger.debug("NODE {}: SECURITY_MESSAGE_ENCAP ({}).", this.getNode().getNodeId(),
				securityPayload.getLogMessage());
		traceHex("SecurityPayloadBytes", securityPayload.getMessageBytes());
		SerialMessage message = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
				SerialMessageType.Request, SerialMessageClass.ApplicationCommandHandler, SECURITY_MESSAGE_PRIORITY);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write((byte) this.getNode().getNodeId());
		baos.write(securityPayload.getLength() + 20);
		baos.write(this.getCommandClass().getKey());
		byte commandClass = SECURITY_MESSAGE_ENCAP;
		if(payloadEncapsulationQueue.size() > 0 && USE_SECURITY_MESSAGE_ENCAP_NONCE_GET) {
			logger.debug("NODE {}: using SECURITY_MESSAGE_ENCAP_NONCE_GET with queue size of {}",
					this.getNode().getNodeId(), payloadEncapsulationQueue.size());
			commandClass = SECURITY_MESSAGE_ENCAP_NONCE_GET;
		}
		baos.write(commandClass);
		// create the iv
		byte[] initializationVector = new byte[16];
		if (USE_SECURE_CRYPTO_PRACTICES) {
			byte[] nonceBytes = nonceTable.generateNewNonce().getNonceBytes();
			// Generate a new nonce.  Fill the entire thing as the 2nd half will be overwritten below
			System.arraycopy(nonceBytes, 0, initializationVector, 0, HALF_OF_IV);
		} else {
			// Fill the entire thing as the 2nd half will be overwritten below
			Arrays.fill(initializationVector, (byte) 0xAA);
		}
		// the 2nd half of the IV is the nonce provided by the device
		System.arraycopy(deviceNonce, 0, initializationVector, HALF_OF_IV, HALF_OF_IV);

		try {
			/*
			 * Append the first 8 bytes of the initialization vector to the message. The remaining 8 bytes are the NONCE
			 * we received from the node, and is committed from sending back to the Node. But we use the full 16 bytes of
			 * the IV to encrypt our message.
			 */
			baos.write(initializationVector, 0, HALF_OF_IV);

			int totalParts = securityPayload.getTotalParts();
			if(totalParts < 1 || totalParts > 2) {
				logger.error("NODE {}: securityPayload had invalid number of parts: {}   aborted send.",
						this.getNode().getNodeId(), totalParts);
				return;
			}
			// at most, the payload will be securityPayload length + 1 byte for the sequence byte
			byte[] plaintextMessageBytes = new byte[1 + securityPayload.getLength()];
			plaintextMessageBytes[0] = securityPayload.getSequenceByte();
			System.arraycopy(securityPayload.getMessageBytes(), 0, plaintextMessageBytes, 1,
					securityPayload.getLength());
			// Append the message payload after encrypting it with AES-OFB (key is EncryptPassword,
			// full IV (16 bytes - 8 Random and 8 NONCE) and payload
			traceHex("Input frame for encryption:", plaintextMessageBytes);
			traceHex("IV:", initializationVector);

			// This will use hardware AES acceleration when possible (default in JDK 8)
			Cipher encryptCipher = Cipher.getInstance("AES/OFB/NoPadding");
			encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, new IvParameterSpec(initializationVector));
			byte[] ciphertextBytes = encryptCipher.doFinal(plaintextMessageBytes);
			traceHex("Encrypted Output", ciphertextBytes);
			baos.write(ciphertextBytes);
			// Append the nonce identifier which is the first byte of the device nonce
			baos.write(deviceNonce[0]);
			int commandClassByteOffset = 2;
			int toMacLength = baos.toByteArray().length - commandClassByteOffset; // Start at command class byte
			byte[] toMac = new byte[toMacLength];
			System.arraycopy(baos.toByteArray(), commandClassByteOffset, toMac, 0, toMacLength);
			// Generate the MAC
			byte sendingNode = (byte) this.getController().getOwnNodeId();
			byte[] mac = generateMAC(commandClass, ciphertextBytes, sendingNode, (byte) getNode().getNodeId(),
					initializationVector);
			traceHex("Auth mac", mac);
			baos.write(mac);
			byte[] payload = baos.toByteArray();
			debugHex("NODE "+this.getNode().getNodeId()+": Outgoing encrypted message", payload);
			message.setMessagePayload(payload);
			if(inclusionStateTracker != null) {
				// if the message we just sent is SECURITY_NETWORK_KEY_SET, then we need to change our Network Key
				// to use the real key, as the reply we will get back will be encrypted with the real Network key
				if (bytesAreEqual(securityPayload.getMessageBytes()[0], 0x98) // 0x98=security class
						&& bytesAreEqual(securityPayload.getMessageBytes()[1], SECURITY_NETWORK_KEY_SET)) {
					logger.info("NODE {}: Setting Network Key to real key after SECURITY_NETWORK_KEY_SET", this.getNode().getNodeId());
					setupNetworkKey(false);
				}
				// We are in inclusion mode, set the message on the tracker so it will be picked
				// up by ZWaveNodeStageAdvancer
				inclusionStateTracker.setNextRequest(message);
			} else { // Send it out through the controller
				this.getController().sendData(message);
			}
		} catch (GeneralSecurityException e) {
			logger.error("NODE {}: Error in sendNextMessageWithNonce, message not sent", e);
		} catch (IOException e) {
			logger.error("NODE {}: Error in sendNextMessageWithNonce, message not sent", e);
		}
	}

	private boolean checkRealNetworkKeyLoaded() {
		if(realNetworkKey == null) {
			String errorMessage = "NODE "+this.getNode()+": Trying to perform secure operation but Network key is NOT set due to: ";
			if(keyException != null) {
				errorMessage += keyException.getMessage();
			}
			logger.error(errorMessage, keyException);
			if(inclusionStateTracker != null) {
				inclusionStateTracker.setErrorState(errorMessage);
			}
			return false;
		}
		return true;
	}

	// package visible for junit
	void setupNetworkKey(boolean useSchemeZero) {
		logger.info("NODE {}: setupNetworkKey useSchemeZero={}",
				this.getNode().getNodeId(), useSchemeZero);
		if(useSchemeZero) {
			logger.info("NODE {}: Using Scheme0 Network Key for Key Exchange since we are in inclusion mode.)",
					this.getNode().getNodeId());
			// Scheme0 network key is a key of all zeros
			networkKey = new SecretKeySpec(new byte[16], AES);
		} else {
			if(!checkRealNetworkKeyLoaded()) {
				return; // Nothing we can do
			}
			// Use the real key
			logger.info("NODE {}: Using Real Network Key.", this.getNode().getNodeId());
			networkKey = realNetworkKey;
		}
		traceHex("Network Key bytes", networkKey.getEncoded());

		try {
			// Derived the message encryption key from the network key
			Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, networkKey);
			encryptKey = new SecretKeySpec(cipher.doFinal(DERIVE_ENCRYPT_KEY), AES);
			traceHex("Encrypt Key", encryptKey.getEncoded());

			// Derived the message auth key from the network key
			cipher.init(Cipher.ENCRYPT_MODE, networkKey);
			authKey = new SecretKeySpec(cipher.doFinal(DERIVE_AUTH_KEY), AES);
			traceHex("Auth Key", authKey.getEncoded());
		} catch (GeneralSecurityException e) {
			logger.error("NODE "+this.getNode().getNodeId()+": Error building derived keys", e);
			keyException = e;
		}
	}

	/**
	 * {@inheritDoc}
	 *
	 * During node inclusion we have to exchange many message with the device to setup
	 * security encapsulation.
	 * <p/>
	 * Ideally, we would create all necessary messages the very first time this method
	 * is called and return the collection.  But that is not achievable due to the following:
	 * 1. Some messages depend on the result of previous responses.
	 * 2. In order to send a security encapsulated message, we need to send a {@link #SECURITY_NONCE_GET},
	 * wait for the {@link #SECURITY_NONCE_REPORT} and use that data to build the message.  Theoretically
	 * we could send many of these at once and get the replies, but they are valid for as little as 3
	 * seconds so they would expire before we the message that used the nonce would ever reach the device.
	 * <p/>
	 * Since we can't create all messages at once, we create a helper {@link ZWaveSecureInclusionStateTracker}
	 * which keeps track of where we are at in the flow and hold the next message to be sent.
	 * <p/>
	 * In addition, this method is typically invoked by {@link ZWaveController.ZWaveInputThread} which means
	 * that as long as the thread is here, we will not receive any incoming messages such as {@link #SECURITY_NONCE_REPORT}.
	 * In that case, we return an empty collection to indicate that we are still waiting for a response message.
	 *
	 * @return One or more {@link SerialMessage} to be sent OR a zero length collection if we are still waiting for a response OR
	 * null if the secure pairing process has completed
	 */
	@Override
	public Collection<SerialMessage> initialize(boolean firstIteration) {
		if(logger.isTraceEnabled()) {
			logger.error("call from NodeAdvancer initialize", new IllegalStateException("show me for thread "+Thread.currentThread().getName()));
		}
		boolean wasThisNodeJustIncluded = wasThisNodeJustIncluded();
		logger.debug("NODE {}: call from NodeAdvancer initialize, firstIteration={}, wasThisNodeJustIncluded={}, keyVerifyReceived={}",
				this.getNode().getNodeId(), firstIteration, wasThisNodeJustIncluded, securePairingComplete);
		// if we are adding this node, then send SECURITY_SCHEME_GET which
		// will start the Network Key Exchange
		if (wasThisNodeJustIncluded) {
			if(firstIteration && !securePairingComplete) {
				setupNetworkKey(true);
				inclusionStateTracker = new ZWaveSecureInclusionStateTracker(getNode());
				// Need to start things off by sending SECURITY_SCHEME_GET
				SerialMessage message = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
						SerialMessageType.Request, SerialMessageClass.ApplicationCommandHandler, SECURITY_MESSAGE_PRIORITY);
				byte[] payload = {
						(byte) this.getNode().getNodeId(),
						3,
						(byte) getCommandClass().getKey(),
						SECURITY_SCHEME_GET,
						0
				};
				// SchemeGet is unencrypted
				message.setMessagePayload(payload);
				logger.debug("NODE {}: call from NodeAdvancer initialize, handing back message={}",
						this.getNode().getNodeId(), message);
				waitForReplyTimeout = System.currentTimeMillis() + WAIT_TIME_MILLIS;
				return Collections.singletonList(message);
			} else if(inclusionStateTracker == null) {
				// We're done since inclusionStateTracker will only be set to null when
				// SECURITY_COMMANDS_SUPPORTED_REPORT is received and that is our final step
				// in the secure inclusion process
				return null; // Tell ZWaveNodeStageAdvancer to advance to the next stage
			} else { // Normal inclusion flow, get the next message or wait for a response to the current one
				SerialMessage nextMessage = inclusionStateTracker.getNextRequest();
				logger.debug("NODE {}: call from NodeAdvancer initialize, Normal inclusion flow, get the next message or wait for a response to the current one, nextMessage={}",
						this.getNode().getNodeId(), nextMessage);
				if(nextMessage == null) { // There is an outstanding request
					if(inclusionStateTracker.getErrorState() != null) { // Check for errors
						logger.error("NODE {}: Secure Inclusion FAILED at step {}: {}",
								this.getNode().getNodeId(), inclusionStateTracker.getCurrentStep(),
								inclusionStateTracker.getErrorState());
						inclusionStateTracker = null;
						return Collections.emptyList();  // Keep waiting for a response
					} else if(System.currentTimeMillis() < waitForReplyTimeout) {
						return Collections.emptyList();  // Keep waiting for a response
					} else {
						// Too much time has passed, fail
						logger.error("NODE {}: Secure Inclusion FAILED at step {}, no reply received, waitForReplyTimeout={}",
								this.getNode().getNodeId(), inclusionStateTracker.getCurrentStep(), waitForReplyTimeout);
						// TODO: remove the node?

						// End inclusion mode
						getNode().getController().requestAddNodesStop();
						return null; // Tell ZWaveNodeStageAdvancer to advance to the next stage
					}
				} else { // nextMessage != null
					logger.debug("NODE {}: call from NodeAdvancer initialize, handing back message={}",
							this.getNode().getNodeId(), nextMessage);
					waitForReplyTimeout = System.currentTimeMillis() + WAIT_TIME_MILLIS;
					// If the next message is SECURITY_NONCE_GET, then reset the nonce timer since
					// we don't know how much time has passed since we are just sending it now
					if(nextMessage.getMessagePayload()[3] == ZWaveSecurityCommandClass.SECURITY_NONCE_GET) {
						// Reset the nonce timer. The nonce report must be received within 10 seconds.
						requestNonceTimer.reset();
						waitingForNonce.set(true);
					}
					// Send the next request
					return Collections.singletonList(nextMessage);
				}
			}
		} else { // Our node was NOT just included
			if(!securePairingComplete) {
				logger.error("NODE {}: Invalid state! secure inclusion has not completed and we are not in inclusion mode, aborting",
						this.getNode().getNodeId());
				return null;
			}
			// The node was initialized previously and we are connecting to it after an openhab restart
			 else if(firstIteration) { // request the current list of security commands as a sanity check
				SerialMessage message = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
						SerialMessageType.Request, SerialMessageClass.SendData, SECURITY_MESSAGE_PRIORITY);
				byte[] payload = {
						(byte) this.getNode().getNodeId(),
						2,
						(byte) getCommandClass().getKey(),
						SECURITY_COMMANDS_SUPPORTED_GET,
				};
				message.setMessagePayload(payload);
				logger.debug("NODE {}: call from NodeAdvancer initialize, handing back message={}",
						this.getNode().getNodeId(), message);
				waitForReplyTimeout = System.currentTimeMillis() + WAIT_TIME_MILLIS;
				return Collections.singletonList(message);
			} else if(System.currentTimeMillis() > waitForReplyTimeout) {
				logger.error("NODE {}: Got no response to InitialSupportedGet, aborting", this.getNode().getNodeId());
				return null; // Tell ZWaveNodeStageAdvancer to advance to the next stage
			} else {
				// the request was already sent, wait for the nonce exchange and the reply to come
				return Collections.emptyList();
			}
		} // end if wasThisNodeJustIncluded
	}

	/**
	 * @return true if we are in the process of adding a new node, ie the controller
	 * is in inclusion mode
	 */
	private boolean wasThisNodeJustIncluded() {
		ZWaveInclusionEvent lastInclusionEvent = getNode().getController().getLastIncludeSlaveFoundEvent();
		boolean result = false;
		if(lastInclusionEvent != null && lastInclusionEvent.getEvent() == Type.IncludeSlaveFound
				&& getNode().getNodeId() == lastInclusionEvent.getNodeId()) {
			// Check that this node was included very recently
			long twoMinutesAgoMs = System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(2);
			result = lastInclusionEvent.getIncludedAt().getTime() > twoMinutesAgoMs;
		}
		logger.debug("NODE {}: lastInclusionEvent={} returning={}", this.getNode().getNodeId(), lastInclusionEvent, result);
		return result;
	}

	/**
	 * Sends a message to the node requesting a new nonce so we can encapsulate (encrypt) and send our next
	 * {@link ZWaveSecurityPayloadFrame} from {@link #payloadEncapsulationQueue}
	 */
	private synchronized void requestNonce() {
		if (waitingForNonce.get()) {
			return;
		}
		waitingForNonce.set(true);
		this.getController().sendData(buildNonceGet());

		// Due to XStreamOmitField, requestNonceTimer can be null
		if(requestNonceTimer == null) {
			requestNonceTimer = new NonceTimer();
		}
		// Reset the nonce timer. The nonce report must be received within 10 seconds.
		requestNonceTimer.reset();
	}

	private SerialMessage buildNonceGet() {
		SerialMessage result = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
				SerialMessageType.Request, SerialMessageClass.SendData, SECURITY_MESSAGE_PRIORITY);
		byte[] payload = {
				(byte) this.getNode().getNodeId(),
				2,
				(byte) getCommandClass().getKey(),
				SECURITY_NONCE_GET,
		};
		if(OVERRIDE_DEFAULT_TRANSMIT_OPTIONS) {
			logger.debug("NODE {}: Using custom transmit options");
			result.setTransmitOptions(ZWaveController.TRANSMIT_OPTION_ACK | ZWaveController.TRANSMIT_OPTION_AUTO_ROUTE);
		}
		result.setMessagePayload(payload);
		return result;
	}

	/**
	 * Generate the MAC (message authentication code) from a security-encrypted message
	 *
	 * @throws GeneralSecurityException
	 */
	byte[] generateMAC(byte commandClass, byte[] ciphertext, byte sendingNode, byte receivingNode, byte[] iv)
			throws GeneralSecurityException {
		traceHex("generateMAC ciphertext", ciphertext);
		traceHex("generateMAC iv", iv);
		// Build a buffer containing a 4-byte header and the encrypted message data, padded with zeros to a 16-byte
		// boundary.
		int bufferSize = ciphertext.length + 4; // +4 to account for the header
		byte[] buffer = new byte[bufferSize];
		byte[] tempAuth = new byte[16];

		buffer[0] = commandClass;
		buffer[1] = sendingNode;
		buffer[2] = receivingNode;
		buffer[3] = (byte) ciphertext.length;
		System.arraycopy(ciphertext, 0, buffer, 4, ciphertext.length);
		traceHex("generateMAC NetworkKey", networkKey.getEncoded());
		traceHex("generateMAC Raw Auth (minus IV)", buffer);
		logger.debug("NODE {}: Raw Auth (Minus IV) Size:{} ({})", bufferSize, bufferSize + 16);

		// Encrypt the IV with ECB
		Cipher encryptCipher = Cipher.getInstance("AES/ECB/NoPadding");
		encryptCipher.init(Cipher.ENCRYPT_MODE, authKey);
		tempAuth = encryptCipher.doFinal(iv);
		traceHex("generateMAC tmp1", tempAuth);
		// our temporary holding
		byte[] encpck = new byte[16];
		int block = 0;

		// now xor the buffer with our encrypted IV
		for (int i = 0; i < bufferSize; i++) {
			encpck[block] = buffer[i];
			block++;
			// if we hit a blocksize, then xor and encrypt
			if (block == 16) {
				for (int j = 0; j < 16; j++) {
					// here we do our xor
					tempAuth[j] = (byte) (encpck[j] ^ tempAuth[j]);
					encpck[j] = 0;
				}
				// reset encpck for good measure
				Arrays.fill(encpck, (byte) 0);
				// reset our block counter back to 0
				block = 0;

				encryptCipher.init(Cipher.ENCRYPT_MODE, authKey);
				tempAuth = encryptCipher.doFinal(tempAuth);
			}
		}

		// any left over data that isn't a full block size
		if (block > 0) {
			for (int i = 0; i < 16; i++) {
				// encpck from block to 16 is already guaranteed to be 0 so its safe to xor it with out tempAuth
				tempAuth[i] = (byte) (encpck[i] ^ tempAuth[i]);
			}

			encryptCipher.init(Cipher.ENCRYPT_MODE, authKey);
			tempAuth = encryptCipher.doFinal(tempAuth);
		}
		// we only care about the first 8 bytes of tempAuth as the mac
		traceHex("generateMAC Computed Auth", tempAuth);
		byte[] mac = new byte[8];
		System.arraycopy(tempAuth, 0, mac, 0, 8);
		return mac;
	}

	/**
	 * Complex as in hard to understand what's going on
	 * @deprecated use {@link #generateMAC(byte, byte[], byte, byte, byte[]) instead
	 */
	@Deprecated
	byte[] generateMACComplex(byte[] data, int length, byte sendingNode, byte receivingNode, byte[] iv)
			throws GeneralSecurityException {
		traceHex("data", data);
		traceHex("iv", iv);
		// Build a buffer containing a 4-byte header and the encrypted message data, padded with zeros to a 16-byte
		// boundary.
		byte[] buffer = new byte[256];
		byte[] tempAuth = new byte[16];

		buffer[0] = data[0]; // Security command class command
		buffer[1] = sendingNode;
		buffer[2] = receivingNode;
		byte copyLength = (byte) (length - 19); // Subtract 19 to account for the 9 security command class bytes that
												// come before and after the encrypted data
		buffer[3] = copyLength;
		System.arraycopy(data, 9, buffer, 4, copyLength); // Copy the cipher bytes over

		int bufferSize = copyLength + 4; // +4 to account for the header above
		traceHex("Raw Auth (minus IV)", buffer);

		// Encrypt the IV with ECB
		Cipher encryptCipher = Cipher.getInstance("AES/ECB/NoPadding");
		encryptCipher.init(Cipher.ENCRYPT_MODE, authKey);
		tempAuth = encryptCipher.doFinal(iv);
		// our temporary holding
		byte[] encpck = new byte[16];
		int block = 0;

		// now xor the buffer with our encrypted IV
		for (int i = 0; i < bufferSize; i++) {
			encpck[block] = buffer[i];
			block++;
			// if we hit a blocksize, then encrypt
			if (block == 16) {
				for (int j = 0; j < 16; j++) {
					// here we do our xor
					tempAuth[j] = (byte) (encpck[j] ^ tempAuth[j]);
					encpck[j] = 0;
				}
				// reset encpck for good measure
				Arrays.fill(encpck, (byte) 0);
				// reset our block counter back to 0
				block = 0;

				encryptCipher.init(Cipher.ENCRYPT_MODE, authKey);
				tempAuth = encryptCipher.doFinal(tempAuth);
				traceHex("BAD tmp2", tempAuth);
			}
		}
		// any left over data that isn't a full block size
		if (block > 0) {
			for (int i = 0; i < 16; i++) {
				// encpck from block to 16 is already guaranteed to be 0 so its safe to xor it with out tmpmac
				tempAuth[i] = (byte) (encpck[i] ^ tempAuth[i]);
			}
			encryptCipher.init(Cipher.ENCRYPT_MODE, authKey);
			tempAuth = encryptCipher.doFinal(tempAuth);
		}
		/* we only care about the first 8 bytes of tmpauth as the mac */
		traceHex("Computed Auth", tempAuth);
		byte[] mac = new byte[8];
		System.arraycopy(tempAuth, 0, mac, 0, 8);
		return mac;
	}

	/**
	 * Utility method to do unsigned byte comparison. This is necessary since in java all primitives are signed but
	 * zwave we often represent values in hex (which is unsigned).
	 *
	 * @param aByte
	 *            a byte
	 * @param anotherByte
	 *            an int
	 * @return true if they are equal
	 */
	public static boolean bytesAreEqual(byte aByte, int anotherByte) {
		return aByte == ((byte) (anotherByte & 0xff));
	}

	/**
	 * Used to set the security key from the config file
	 * @param hexString a comma separated hex string, for example: (please DO NOT use this as your key!)
	 * 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
	 */
	public static void setRealNetworkKey(String hexString) {
		try {
			byte[] keyBytes = hexStringToByteArray(hexString);
			ZWaveSecurityCommandClass.realNetworkKey = new SecretKeySpec(keyBytes, "AES");
			logger.info("Update networkKey");
			ZWaveSecurityCommandClass.keyException = null; // we have a valid key
		} catch (IllegalArgumentException e) {
			logger.error("Error parsing zwave:networkKey", e);
			ZWaveSecurityCommandClass.keyException = e;
		}
	}

	public static String commandToString(int command) {
		Byte theByte = Byte.valueOf((byte) (command & 0xff));
		final String result = COMMAND_LOOKUP_TABLE.get(theByte);
		if(result == null) {
			return "unknown";
		}
		return result;
	}

	// TODO: remove all traceHex and use SerialMessage.bbToHex instead
	/**
	 * Utility method to dump a byte array as hex. Will only print the data if debug
	 * mode is debug logging is actually enabled.  We don't use {@link SerialMessage#bb2hex(byte[])}
	 * because we need our debug format to match that of OZW
	 *
	 * @param description
	 *            a human readable description of the data being logged
	 * @param bytes
	 *            the bytes to convert to hex and log
	 * @param offset
	 *            where to start from; zero means log the full byte array
	 */
	private void traceHex(String description, byte[] bytes, int offset, int length) {
		if (!logger.isTraceEnabled()) {
			return;
		}
		StringBuilder buf = new StringBuilder();
		for (int i = offset; i < offset + length; i++) {
			buf.append(String.format("0x%02x, ", (bytes[i] & 0xff)));
		}
		logger.trace("{}={}", description, buf.toString());
	}

	private void traceHex(String description, byte[] bytes, int offset) {
		traceHex(description, bytes, offset, bytes.length - offset);
	}

	private void debugHex(String description, byte[] bytes, int offset, int length) {
		if (!logger.isDebugEnabled()) {
			return;
		}
		StringBuilder buf = new StringBuilder();
		for (int i = offset; i < offset + length; i++) {
			buf.append(String.format("0x%02x, ", (bytes[i] & 0xff)));
		}
		logger.debug("{}={}", description, buf.toString());
	}

	private void debugHex(String description, byte[] bytes) {
		int offset = 0;
		debugHex(description, bytes, offset, bytes.length - offset);
	}

	/**
	 * Utility method to dump a byte array as hex. Will only print the data if debug mode is debug logging is actually
	 * enabled
	 *
	 * @param description
	 *            a human readable description of the data being logged
	 * @param bytes
	 *            the bytes to convert to hex and log
	 */
	private void traceHex(String description, byte[] messagePayload) {
		traceHex(description, messagePayload, 0, messagePayload.length);
	}


	private static SecureRandom createNewSecureRandom() {
		SecureRandom secureRandom = null;
		// SecureRandom advice taken from
		// http://www.cigital.com/justice-league-blog/2009/08/14/proper-use-of-javas-securerandom/
		try {
			secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
		} catch (GeneralSecurityException e) {
			secureRandom = new SecureRandom();
		}
		// force an internal seeding
		secureRandom.nextBoolean();
		// Add some entropy of our own to the seed
		secureRandom.setSeed(Runtime.getRuntime().freeMemory());
		for(File root : File.listRoots()) {
			secureRandom.setSeed(root.getUsableSpace());
		}
		return secureRandom;
	}

	public static byte[] hexStringToByteArray(String hexStringParam) {
		String hexString = hexStringParam.replace("0x", "");
		hexString = hexString.replace(",", "");
		hexString = hexString.replace(" ", "");
		// from https://stackoverflow.com/questions/23354999/hex-string-to-byte-array-conversion
		if ((hexString.length() % 2) != 0)
	        throw new IllegalArgumentException("Input string must contain an even number of characters");

	    final byte result[] = new byte[hexString.length()/2];
	    final char enc[] = hexString.toCharArray();
	    for (int i = 0; i < enc.length; i += 2) {
	        StringBuilder curr = new StringBuilder(2);
	        curr.append(enc[i]).append(enc[i + 1]);
	        result[i/2] = (byte) Integer.parseInt(curr.toString(), 16);
	    }
	    return result;
	}


	/**
	 * per the spec we must track how long it has been since we
	 * sent a nonce and only allow it's use within a specified
	 * time period.
	 */
	static class NonceTimer {
		private long start = System.currentTimeMillis();

		void reset() {
			start = System.currentTimeMillis();
		}

		private boolean isExpired() {
			return System.currentTimeMillis() > (start + NONCE_MAX_MILLIS);
		}
	}

	/**
	 * Class to hold the nonce itself and the it's related data
	 */
	private static class Nonce {
		private final byte[] nonceBytes;
		private final NonceTimer timer;
		private final byte nonceId;

		private Nonce(byte[] nonceBytes, NonceTimer timer) {
			super();
			this.nonceBytes = nonceBytes;
			this.timer = timer;
			this.nonceId = nonceBytes[0];
		}

		private byte[] getNonceBytes() {
			return nonceBytes;
		}

		private NonceTimer getTimer() {
			return timer;
		}

		private byte getNonceId() {
			return nonceId;
		}
	}

	/**
	 * Data store to hold the nonces we have generated and
	 * provide a method to cleanup old nonces
	 *
	 */
	private class NonceTable {
		private SecureRandom secureRandom = null;
		private Map<Byte, Nonce> table = new ConcurrentHashMap<Byte, Nonce>();
		private long reseedAt = 0L;

		private NonceTable() {
			super();
		}

		private Nonce generateNewNonce() {
			if(System.currentTimeMillis() > reseedAt) {
				secureRandom = createNewSecureRandom();
				reseedAt = System.currentTimeMillis() + SECURE_RANDOM_RESEED_INTERVAL_MILLIS;
			}
			cleanup();
			byte[] nonceBytes = new byte[8];
			secureRandom.nextBytes(nonceBytes);
			// Make sure the id is unique for all currently valid nonces
			while(getNonceById(nonceBytes[0]) != null) {
				secureRandom.nextBytes(nonceBytes);
			}
			Nonce nonce = new Nonce(nonceBytes, new NonceTimer());
			table.put(nonce.getNonceId(), nonce);
			return nonce;
		}

		private Nonce getNonceById(byte id) {
			cleanup();
			// Nonces can only be used once so remove it
			return table.remove(id);
		}

		/**
		 * Remove any expired nonces from our table
		 */
		private void cleanup() {
			Iterator<Entry<Byte, Nonce>> iter = table.entrySet().iterator();
			while(iter.hasNext()) {
				Nonce nonce = iter.next().getValue();
				if(nonce.getTimer().isExpired()) {
					logger.warn(String.format("NODE %s: Expiring nonce with id=0x%02X",
							ZWaveSecurityCommandClass.this.getNode().getNodeId(), nonce.getNonceId()));
					iter.remove();
				}
			}
		}
	}

}
