package org.openhab.binding.zwave.internal.protocol.commandclass;

import junit.framework.TestCase;

import org.junit.Test;
import org.openhab.binding.zwave.internal.protocol.commandclass.ZWaveUserCodeCommandClass.UserCode;

/**
 * @author Dave Badia
 * @since 1.8.0
 */
public class ZWaveUserCodeCommandClassTest extends TestCase {

	@Test
	public void testValidateUserCode_MinLength() throws Exception {
		String code = buildCode(ZWaveUserCodeCommandClass.USER_CODE_MIN_LENGTH);
		UserCode userCode = new UserCode("dave", code);
		boolean result = ZWaveUserCodeCommandClass.userCodeIsValid(userCode, 1);
		assertTrue(result);
	}

	@Test
	public void testValidateUserCode_MaxLength() throws Exception {
		String code = buildCode(ZWaveUserCodeCommandClass.USER_CODE_MAX_LENGTH);
		UserCode userCode = new UserCode("dave", code);
		boolean result = ZWaveUserCodeCommandClass.userCodeIsValid(userCode, 1);
		assertTrue(result);
	}

	@Test
	public void testValidateUserCode_NegativeTooBig() throws Exception {
		String code = buildCode(ZWaveUserCodeCommandClass.USER_CODE_MAX_LENGTH + 1);
		UserCode userCode = new UserCode("dave", code);
		boolean result = ZWaveUserCodeCommandClass.userCodeIsValid(userCode, 1);
		assertFalse(result);
	}

	@Test
	public void testValidateUserCode_NegativeTooSmall() throws Exception {
		String code = buildCode(ZWaveUserCodeCommandClass.USER_CODE_MIN_LENGTH - 1);
		UserCode userCode = new UserCode("dave", code);
		boolean result = ZWaveUserCodeCommandClass.userCodeIsValid(userCode, 1);
		assertFalse(result);
	}

	@Test
	public void testValidateUserCode_NegativeHasAlphaCharacterInBeginning() throws Exception {
		String code = "a"+buildCode(4);
		UserCode userCode = new UserCode("dave", code);
		boolean result = ZWaveUserCodeCommandClass.userCodeIsValid(userCode, 1);
		assertFalse(result);
	}

	@Test
	public void testValidateUserCode_NegativeHasAlphaCharacterAtEnd() throws Exception {
		String code = buildCode(4)+"a";
		UserCode userCode = new UserCode("dave", code);
		boolean result = ZWaveUserCodeCommandClass.userCodeIsValid(userCode, 1);
		assertFalse(result);
	}

	/**
	 * In the future, codes will be entered in a gui, so we want to be able to
	 * accept null for node id
	 */
	@Test
	public void testValidateUserCode_NullNodeId() throws Exception {
		String code = buildCode(ZWaveUserCodeCommandClass.USER_CODE_MIN_LENGTH);
		UserCode userCode = new UserCode("dave", code);
		boolean result = ZWaveUserCodeCommandClass.userCodeIsValid(userCode, null);
		assertTrue(result);
	}

	/* ******************** util methods ************************/

	private String buildCode(int length) {
		StringBuilder buf = new StringBuilder(length);
		for (int i = 0; i < length; i++) {
			buf.append(i);
		}
		return buf.toString();
	}
}
