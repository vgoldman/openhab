package org.openhab.binding.zwave.internal.protocol.commandclass;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.openhab.binding.zwave.internal.protocol.SerialMessage;
import org.openhab.binding.zwave.internal.protocol.ZWaveNode;
import org.openhab.binding.zwave.internal.protocol.commandclass.ZWaveCommandClass.CommandClass;

import com.thoughtworks.xstream.annotations.XStreamOmitField;

/**
 * Used only by {@link ZWaveSecurityCommandClass}
 *
 * ZWave security protocol that certain messages be "security encapsulated"
 * (that is, encrypted and signed).  The first step to send a {@link SerialMessage}
 * securely is break down the payload into one or more security payload frames
 * that will then be queued up in {@link ZWaveSecurityCommandClass}
 *
 * @see {@link ZWaveSecurityCommandClass#queueMessageForEncapsulation}
 * @author Dave Badia
 * @since 1.8.0
 */
public class ZWaveSecurityPayloadFrame {

	/**
	 * The largest amount of payload we can fit into a single
	 * {@link ZWaveSecurityPayloadFrame}. {@link SerialMessage} contents larger than this
	 * must be split into multiple {@link ZWaveSecurityPayloadFrame}
	 */
	private static final int SECURITY_PAYLOAD_ONE_PART_SIZE = 28;

	/**
	 * Sequence byte is zero for messages that fit in a single frame
	 */
	static final byte SEQUENCE_BYTE_FOR_SINGLE_FRAME_MESSAGE = 0;

	/**
	 *	Every <b>set</b> of multi frame messages must have unique sequence number.
	 */
	@XStreamOmitField
	private static final AtomicInteger sequenceCounter = new AtomicInteger(0);

	private final int partNumber;
	private final int totalParts;
	private final byte sequenceByte;
	private final byte[] partBytes;
	private final String logMessage;

	public static List<ZWaveSecurityPayloadFrame> convertToSecurityPayload(ZWaveNode node, byte[] payloadBuffer, String logString) {
		List<ZWaveSecurityPayloadFrame> list = new ArrayList<ZWaveSecurityPayloadFrame>();
		/*
		 *  The sequence data in a single byte.  The entire byte is zero if the whole
		 *  message fit into one frame.  If multiple frames are required:
		 *   1st 2 bits: 	reserved, always 0
		 *   3rd bit: 		second frame: 0 for 1st frame, 1 for second frame
		 *   4th bit:		sequenced: 	0 if the entire message fits in one frame; 1 if more than 1 are required
		 *   last 4 bits:	sequence counter - used to tell groups of sequenced messages apart.
		 *   					Must be the same for part 1 and part 2 of a sequenced message
		 */
		if (payloadBuffer.length > SECURITY_PAYLOAD_ONE_PART_SIZE) {
			// Use this byte for both parts, but OR it for each frame
			byte messageSequnceByte = (byte) sequenceCounter.getAndIncrement();
			// Message must be split into two parts
			byte[] partOneBuffer = new byte[SECURITY_PAYLOAD_ONE_PART_SIZE];
			System.arraycopy(payloadBuffer, 0, partOneBuffer, 0, SECURITY_PAYLOAD_ONE_PART_SIZE);
			byte partOneSequenceByte = (byte) (messageSequnceByte | 0x10); // Sequenced, first frame
			list.add(new ZWaveSecurityPayloadFrame(node, 1, 2, partOneBuffer, partOneSequenceByte, logString));

			byte partTwoSequenceByte = (byte) (messageSequnceByte | 0x30); // Sequenced, second frame
			int part2Length = payloadBuffer.length - SECURITY_PAYLOAD_ONE_PART_SIZE;
			byte[] partTwoBuffer = new byte[part2Length];
			System.arraycopy(payloadBuffer, SECURITY_PAYLOAD_ONE_PART_SIZE, partTwoBuffer, 0, part2Length);
			list.add(new ZWaveSecurityPayloadFrame(node, 2, 2, payloadBuffer, partTwoSequenceByte, logString));
		} else {
			// The entire message can be encapsulated as one
			list.add(new ZWaveSecurityPayloadFrame(node, payloadBuffer, logString));
		}
		return list;
	}

	private ZWaveSecurityPayloadFrame(ZWaveNode node, int partNumber, int totalParts,
			byte[] messageBuffer, byte sequenceByte, String logMessage) {
		this.partNumber = partNumber;
		this.totalParts = totalParts;
		this.partBytes = new byte[messageBuffer.length];
		System.arraycopy(messageBuffer, 0, partBytes, 0, messageBuffer.length);
		this.sequenceByte = sequenceByte;
		if(messageBuffer.length > 1) {
			this.logMessage = String.format(
					"NODE %s: SecurityPayload (part %d of %d) for %s 0x%02X: %s",
					node.getNodeId(),
					partNumber, totalParts,
					CommandClass.getCommandClass(messageBuffer[0] & 0xff),
					messageBuffer[1], logMessage);
		} else {
			this.logMessage = String.format(
					"NODE %s: SecurityPayload (part %d of %d) for %s : %s",
					node.getNodeId(),
					partNumber, totalParts,
					CommandClass.getCommandClass(messageBuffer[0] & 0xff),
					 logMessage);
		}
	}

	public ZWaveSecurityPayloadFrame(ZWaveNode node, byte[] messageBuffer,
			String logString) {
		this(node, 1, 1, messageBuffer, SEQUENCE_BYTE_FOR_SINGLE_FRAME_MESSAGE, logString);
	}
	public int getTotalParts() {
		return totalParts;
	}

	public String getLogMessage() {
		return logMessage;
	}

	public byte[] getMessageBytes() {
		return partBytes;
	}

	public int getPart() {
		return partNumber;
	}

	public byte getSequenceByte() {
		return sequenceByte;
	}

	public int getLength() {
		return partBytes.length;
	}

	@Override
	public String toString() {
		return logMessage;
	}


}
