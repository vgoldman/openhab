package org.openhab.binding.zwave.internal.protocol.commandclass;

import java.util.Arrays;
import java.util.List;

import org.openhab.binding.zwave.internal.protocol.SerialMessage;
import org.openhab.binding.zwave.internal.protocol.ZWaveNode;
import org.openhab.binding.zwave.internal.protocol.initialization.ZWaveNodeStageAdvancer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Used only by {@link ZWaveSecurityCommandClass} during device inclusion.
 *
 * During device inclusion, the security registration process between us and the node
 * has multiple stages in order to share our network key with the device.  This class
 * is used to track our current state in that process and determine next steps.
 *
 * The specific commands to be exchanged are:
 * {@value #INIT_COMMAND_ORDER_LIST}
 *
 * @author Dave Badia
 * @since 1.8.0
 */
class ZWaveSecureInclusionStateTracker {
	private static final Logger logger = LoggerFactory.getLogger(ZWaveSecureInclusionStateTracker.class);

	/**
	 * During node inclusion <b>only</b>, this is the order in which commands should be sent and received.
	 * Commands absent from this list (for example {@link #SECURITY_MESSAGE_ENCAP}) can be sent/received at any time
	 */
	private final List<Byte> INIT_COMMAND_ORDER_LIST =
			Arrays.asList(new Byte[]{
		ZWaveSecurityCommandClass.SECURITY_SCHEME_GET,
		ZWaveSecurityCommandClass.SECURITY_SCHEME_REPORT,
		ZWaveSecurityCommandClass.SECURITY_NETWORK_KEY_SET,
		ZWaveSecurityCommandClass.SECURITY_NETWORK_KEY_VERIFY,
		ZWaveSecurityCommandClass.SECURITY_COMMANDS_SUPPORTED_GET,
		ZWaveSecurityCommandClass.SECURITY_COMMANDS_SUPPORTED_REPORT,
	});

	private static final boolean HALT_ON_IMPROPER_ORDER = true;

	private byte currentStep = INIT_COMMAND_ORDER_LIST.get(0);

	/**
	 * The next {@link SerialMessage} that will be given to {@link ZWaveNodeStageAdvancer}
	 * when it calls {@link ZWaveSecurityCommandClass#initialize(boolean)}
	 */
	private SerialMessage nextRequestMessage = null;

	/**
	 * Lock object that will be used for synchronization
	 */
	private Object nextMessageLock = new Object();

	private String errorState = null;

	private final ZWaveNode node;

	ZWaveSecureInclusionStateTracker(ZWaveNode node) {
		this.node = node;
	}

	/**
	 * Since these operations are security sensitive we must ensure they are
	 * executing in the proper sequence
	 * @param newStep the state we are about to enter
	 * @return true if the new command was in an acceptable order, false
	 * if it was not.  if false is returned, the response should <b>not</b>
	 * be sent.
	 */
	synchronized boolean verifyAndAdvanceState(Byte newStep) {
		logger.debug(String.format("NODE %s: ZWaveSecurityCommandClass in verifyAndAdvanceState with newstep=0x%02X, currentstep=0x%02X",
				node.getNodeId(), newStep, currentStep));
		if(!INIT_COMMAND_ORDER_LIST.contains(newStep)) {
			// Commands absent from EXPECTED_COMMAND_ORDER_LIST are always ok
			return true;
		}
		// Going back to the first step (zero index) is always OK
		if(INIT_COMMAND_ORDER_LIST.indexOf(newStep) > 0) {
			// We have to verify where we are at
			int currentIndex = INIT_COMMAND_ORDER_LIST.indexOf(currentStep);
			int newIndex = INIT_COMMAND_ORDER_LIST.indexOf(newStep);
			// We sometimes get repeat messages.  Accept those or the next message
			if(newIndex != currentIndex && newIndex - currentIndex != 1) {
				if(HALT_ON_IMPROPER_ORDER) {
					logger.error("NODE {}: Commands received out of order, aborting current={}, new={}",
							node.getNodeId(), currentIndex, newIndex);
					return false;
				} else {
					logger.warn("NODE {}: Commands received out of order (warning only) current={}, new={}",
							node.getNodeId(), currentIndex, newIndex);
					// fall through below
				}
			}
		}
		currentStep = newStep;
		return true;
	}


	public void setErrorState(String errorState) {
		this.errorState = errorState;
	}

	void setNextRequest(SerialMessage message) {
		logger.debug("NODE {}: in InclusionStateTracker.setNextRequest() with {}", node.getNodeId(), message);
		verifyAndAdvanceState((byte) (message.getMessagePayloadByte(3) & 0xff));
		synchronized(nextMessageLock) {
			nextRequestMessage = message;
			nextMessageLock.notify();
		}
	}

	/**
	 * Gets the next message to be sent during the inclusion flow.
	 * Each message can only get retrieved once
	 * @return the next message or null if there was none
	 */
	SerialMessage getNextRequest() {
		synchronized(nextMessageLock) {
			if(nextRequestMessage != null) {
				SerialMessage message = nextRequestMessage;
				nextRequestMessage = null;
				return message;
			}
			return null;
		}
	}

	public byte getCurrentStep() {
		return currentStep;
	}

	public String getErrorState() {
		return errorState;
	}
}