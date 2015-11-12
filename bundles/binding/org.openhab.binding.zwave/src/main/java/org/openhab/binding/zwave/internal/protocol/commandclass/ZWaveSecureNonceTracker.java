package org.openhab.binding.zwave.internal.protocol.commandclass;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.openhab.binding.zwave.internal.protocol.SerialMessage;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessageClass;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessagePriority;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessageType;
import org.openhab.binding.zwave.internal.protocol.ZWaveController;
import org.openhab.binding.zwave.internal.protocol.ZWaveNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ZWaveSecureNonceTracker {
	private static final Logger logger = LoggerFactory.getLogger(ZWaveSecureNonceTracker.class);

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
	 * It's a security best practice to periodically re-seed our random number
	 * generator
	 * http://www.cigital.com/justice-league-blog/2009/08/14/proper-use-of-javas-securerandom/
	 */
	private static final long SECURE_RANDOM_RESEED_INTERVAL_MILLIS = TimeUnit.DAYS.toMillis(1);

	private final ZWaveNode node;


	private NonceTable nonceTable = new NonceTable();

	/**
	 * Timer to track time elapsed between sending {@link #SECURITY_NONCE_GET} and
	 * receiving {@link #SECURITY_NONCE_REPORT}.  If too
	 * much time elapses we should request a new nonce.  This timer is optional
	 * but recommended
	 */
	private NonceTimer requestNonceTimer = null;

	/**
	 * The last nonce received from the device
	 */
	private Nonce lastDeviceNonce = null;

	private SecureRandom secureRandom = null;
	private long reseedAt = 0L;


	ZWaveSecureNonceTracker(ZWaveNode node) {
		this.node = node;
	}

	/**
	 * @return a useable {@link Nonce} or null if none are avaialabe
	 */
	synchronized Nonce getUseableDeviceNonce() {
		logger.debug("NODE {}: getUseableDeviceNonce() lastDeviceNonce=", node.getNodeId(), lastDeviceNonce);
		if(lastDeviceNonce != null && lastDeviceNonce.getTimer().isExpired()) {
			lastDeviceNonce = null;
		}
		return lastDeviceNonce;
	}

	/**
	 * @return true if a nonce has been requested from the node and a reply is pending
	 */
	private synchronized boolean hasNonceBeenRequested() {
		logger.debug("NODE {}: getUseableDeviceNonce() requestNonceTimer={}", node.getNodeId(), requestNonceTimer);
		if(requestNonceTimer != null && !requestNonceTimer.isExpired()) {
			return true;
		} else {
			requestNonceTimer = null;
			return false;
		}
	}

	SerialMessage buildNonceGetIfNeeded() {
		if (hasNonceBeenRequested()) {
			logger.debug("NODE {}: already waiting for nonce", node.getNodeId());
			return null;
		}
		logger.debug("NODE {}: requesting nonce", node.getNodeId());
		SerialMessage message = new SerialMessage(node.getNodeId(), SerialMessageClass.SendData,
				SerialMessageType.Request, SerialMessageClass.ApplicationCommandHandler,
				ZWaveSecurityCommandClass.SECURITY_MESSAGE_PRIORITY);
		byte[] payload = {
				(byte) node.getNodeId(),
				2,
				(byte) ZWaveSecurityCommandClass.getSecurityCommandClass().getKey(),
				ZWaveSecurityCommandClass.SECURITY_NONCE_GET,
		};
		if(ZWaveSecurityCommandClass.OVERRIDE_DEFAULT_TRANSMIT_OPTIONS) {
			logger.trace("NODE {}: Using custom transmit options", node.getNodeId());
			message.setTransmitOptions(ZWaveController.TRANSMIT_OPTION_ACK | ZWaveController.TRANSMIT_OPTION_AUTO_ROUTE);
		}
		// We only try once as strange things happen with NONCE_GET requests TODO: add more detail as to what we are trying to fix here
//		message.attempts = 1; // TODO: do I really need this?
		message.setMessagePayload(payload);
		if(requestNonceTimer != null) {
			logger.warn("NODE {}: requestNonceTimer != null but generating a new request", node.getNodeId() );
		}
		requestNonceTimer = new NonceTimer(NonceTimerType.REQUESTED, node);
		return message;
	}


	/**
	 * Generate a new nonce, then build a SECURITY_NONCE_REPORT
	 */
	SerialMessage generateAndBuildNonceReport() {
		byte[] nonceBytes = generateNonceBytes();

		// Make sure the id is unique for all currently valid nonces
		// Can't have duplicate 1st bytes since that is the nonce ID
		nonceTable.cleanup();
		while(USE_SECURE_CRYPTO_PRACTICES && nonceTable.getNonceById(nonceBytes[0]) != null) {
			nonceBytes = generateNonceBytes();
		}
		Nonce nonce = new Nonce(nonceBytes, new NonceTimer(NonceTimerType.GENERATED, node));
		nonceTable.addNonceGeneratedForDevice(nonce);

		// SECURITY_NONCE_REPORT gets immediate priority
		SerialMessage message = new SerialMessage(node.getNodeId(), SerialMessageClass.SendData,
				SerialMessageType.Request, SerialMessageClass.ApplicationCommandHandler, SerialMessagePriority.Immediate);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write((byte) node.getNodeId());
		baos.write((byte) 10);
		baos.write((byte) ZWaveSecurityCommandClass.getSecurityCommandClass().getKey());
		baos.write(ZWaveSecurityCommandClass.SECURITY_NONCE_REPORT);
		try {
			baos.write(nonceBytes);
			message.setMessagePayload(baos.toByteArray());
			if(ZWaveSecurityCommandClass.OVERRIDE_DEFAULT_TRANSMIT_OPTIONS) {
				logger.trace("NODE {}: Using custom transmit options", node.getNodeId());
				message.setTransmitOptions(ZWaveController.TRANSMIT_OPTION_ACK | ZWaveController.TRANSMIT_OPTION_AUTO_ROUTE);
			}
		} catch (IOException e) {
			logger.error("NODE {}: Error during Security sendNonceReport.", node.getNodeId(), e);
			return null;
		}
		return message;
	}

	/**
	 * Called by {@link ZWaveSecurityCommandClass} so the nonce tracker is aware that
	 * a nonce request is being sent via SECURITY_MESSAGE_ENCAP_NONCE_GET and our timer should be started
	 */
	void sendingEncapNonceGet() {
		// No requestNonceTimer != null check since this will be called multiple times for teh same
		requestNonceTimer = new NonceTimer(NonceTimerType.REQUESTED, node);
	}

	void receivedNonceFromDevice(byte[] nonceBytes) {
		if(requestNonceTimer == null) {
			logger.warn("NODE {}: nonce was received, but we have no requestNonceTimer", node.getNodeId());
		} else if(requestNonceTimer.isExpired()) {
			// The nonce was not received within the alloted time of us sending the nonce request. Send it again
			logger.warn("NODE {}: nonce was not received within {}ms, a new one will be requested.",
					node.getNodeId(), NonceTimerType.REQUESTED.validityInMillis);
			// The ZWaveSecurityEncapsulationThread will request a new one for us
			return;
		}

		requestNonceTimer = null;
		if(lastDeviceNonce != null) {
			logger.warn("NODE {}: Received new nonce from device, ejecting {}.",
				node.getNodeId(), lastDeviceNonce);
		}
		lastDeviceNonce = new Nonce(nonceBytes, new NonceTimer(NonceTimerType.RECEIVED, node));
	}

	Nonce getNonceWeGeneatedById(byte nonceId) {
		Nonce nonce = nonceTable.getNonceById(nonceId);
		if(nonce == null) {
			logger.error(String.format("NODE %s: Could not find nonce (probably expired) for id=0x%02X in table=%s",
					node.getNodeId(), nonceId, nonceTable));
		}
		return nonce;
	}

	byte[] generateNonceForEncapsulationMessage() {
		return generateNonceBytes();
	}

	private byte[] generateNonceBytes() {
		if (!USE_SECURE_CRYPTO_PRACTICES) {
			return Nonce.INSECURE_NONCE_BYTES;
		}
		if(System.currentTimeMillis() > reseedAt) {
			secureRandom = createNewSecureRandom();
			reseedAt = System.currentTimeMillis() + SECURE_RANDOM_RESEED_INTERVAL_MILLIS;
		}
		byte[] nonceBytes = new byte[8];
		secureRandom.nextBytes(nonceBytes);
		return nonceBytes;
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

	/*       	--------------	Begin inner classes --------------		*/


	/**
	 * The type of Nonce
	 */
	private static enum NonceTimerType {
		/**
		 * Optional but recommended, so we implement it.
		 * Is triggered when we send a {@link ZWaveSecurityCommandClass#SECURITY_NONCE_GET}
		 */
		REQUESTED(TimeUnit.SECONDS.toMillis(20)), // 20 seconds since this is optional anyway

		/**
		 * Required and is triggered when we generate a nonce to send to the device
		 * via a {@link ZWaveSecurityCommandClass#SECURITY_NONCE_REPORT}.
		 * Represents how long the device has to use the nonce we sent from the time we
		 * generated it (NOT the time we received the ack).  min=3, recommended=10, max=20
		 */
		GENERATED(TimeUnit.SECONDS.toMillis(10)),
		/**
		 * Is used to estimate if a nonce we received from a device is still
		 * useful.  We have no way of knowing for sure, as nonces can be valid
		 * for as little as 3 but as many as 20 seconds.  Also, the devices
		 * timer starts when it sends the nonce, not when we get it.  So slow
		 * transmission time can also cause the nonce to be unusable.
		 *
		 */
		// TODO: DB track if nonce used are from ENCAP_GET_NONCE, and if those keep failing, disable the use
		// of them since the device has a short timer
		RECEIVED(TimeUnit.SECONDS.toMillis(5)), // 5 seconds is our best guess

		/**
		 * No timer required.  Typically used when we generate a nonce to include in a
		 * {@link ZWaveSecurityCommandClass#SECURITY_MESSAGE_ENCAP} or
		 * {@link ZWaveSecurityCommandClass#SECURITY_MESSAGE_ENCAP_NONCE_GET} message
		 */
		NONE(Long.MAX_VALUE)
		;

		private final long generatedAt = System.currentTimeMillis();
		private final long validityInMillis;

		private NonceTimerType(long validityInMillis) {
			this.validityInMillis = validityInMillis;
		}

		private long computeExpiresAt() {
			return System.currentTimeMillis() + validityInMillis;
		}
	}

	/**
	 * per the spec we must track how long it has been since we
	 * sent a nonce and only allow it's use within a specified
	 * time period.
	 */
	static class NonceTimer {
		private NonceTimerType type;
		private long expiresAt;
		private int nodeId;

		NonceTimer(NonceTimerType type, ZWaveNode node) {
			this.type = type;
			this.nodeId = node.getNodeId();
			reset();
		}

		void reset() {
			expiresAt = type.computeExpiresAt();
		}

		/**
		 * @return ms left before this nonce expires, or a negative number if
		 * it has already expired
		 */
		private long getTimeLeft() {
			return expiresAt - System.currentTimeMillis();
		}

		private boolean isExpired() {
			long now = System.currentTimeMillis();
			boolean expired = getTimeLeft() < 0;
			if(logger.isTraceEnabled()) {
				DateFormat dateFormatter = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");
				logger.trace("NODE {}: expiresAt={} now={}, expired={}",
						nodeId, dateFormatter.format(expiresAt), dateFormatter.format(now), expired);
			}
			return expired;
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append("NonceTimer [type=").append(type).append("  expired=").append(isExpired())
			.append("  getTimeLeft=").append(getTimeLeft()).append("]");
			return builder.toString();
		}
	}

	/**
	 * Class to hold the nonce itself and the it's related data
	 */
	static class Nonce {
		private static final byte[] INSECURE_NONCE_BYTES = new byte[]{(byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, };
		private byte[] nonceBytes;
		private NonceTimer timer;
		private byte nonceId;

		/**
		 * Generates a nonce to be sent to a device in
		 * a {@link ZWaveSecurityCommandClass#SECURITY_NONCE_REPORT} message
		 * @param nonceBytes
		 * @param timer the timer should be used, can be null
		 */
		private Nonce(byte[] nonceBytes, NonceTimer timer) {
			super();
			if(nonceBytes == null || nonceBytes.length != 8) {
				throw new IllegalArgumentException("Invalid nonce length for "+Arrays.toString(nonceBytes));
			}
			this.nonceBytes = nonceBytes;
			this.nonceId = nonceBytes[0];
			this.timer = timer;
		}

		byte[] getNonceBytes() {
			return nonceBytes;
		}

		/**
		 * @return the timer or null if none was used
		 */
		private NonceTimer getTimer() {
			return timer;
		}

		private byte getNonceId() {
			return nonceId;
		}

		@Override
		public String toString() {
			StringBuilder buf = new StringBuilder("Nonce ");
			if(timer != null) {
				buf.append(timer.type).append("   ");
			}
			buf.append(SerialMessage.bb2hex(nonceBytes));
			if(timer != null) {
				buf.append("; time left=").append(timer.getTimeLeft());
			}
			return buf.toString();
		}

		@Override
		public int hashCode() {
			int prime = 31;
			int result = 1;
			result = prime * result + Arrays.hashCode(nonceBytes);
			result = prime * result + nonceId;
			result = prime * result + ((timer == null) ? 0 : timer.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			Nonce other = (Nonce) obj;
			if (!Arrays.equals(nonceBytes, other.nonceBytes)) {
				return false;
			}
			if (nonceId != other.nonceId) {
				return false;
			}
			if (timer == null) {
				if (other.timer != null) {
					return false;
				}
			} else if (!timer.equals(other.timer)) {
				return false;
			}
			return true;
		}
	}

	/**
	 * Data store to hold the nonces we have generated and
	 * provide a method to cleanup old nonces
	 *
	 */
	private class NonceTable {
		private Map<Byte, Nonce> table = new ConcurrentHashMap<Byte, Nonce>();

		private NonceTable() {
			super();
		}

		/**
		 * called when this nonce will be sent to a device
		 * in a {@link ZWaveSecurityCommandClass#SECURITY_NONCE_REPORT} message
		 *
		 */
		void addNonceGeneratedForDevice(Nonce nonce) {
			table.put(nonce.getNonceId(), nonce);
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
				if(nonce.getTimer() != null && nonce.getTimer().isExpired()) {
					logger.warn(String.format("NODE %s: Expiring nonce with id=0x%02X",
							node.getNodeId(), nonce.getNonceId()));
					iter.remove();
				}
			}
		}

		@Override
		public String toString() {
			StringBuilder buf = new StringBuilder("NonceTable: [");
			for(Nonce nonce : table.values()) {
				buf.append(nonce.toString()).append("    ");
			}
			return buf.toString();
		}
	}
}
