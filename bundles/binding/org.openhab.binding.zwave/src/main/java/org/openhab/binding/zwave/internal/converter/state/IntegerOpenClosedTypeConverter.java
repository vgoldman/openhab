/**
 * Copyright (c) 2010-2015, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.zwave.internal.converter.state;

import org.openhab.binding.zwave.internal.converter.ZWaveDoorLockConverter;
import org.openhab.core.library.types.OpenClosedType;

/**
 * Converts from a Z-Wave integer value to a {@link OpenClosedType}
 * @author Jan-Willem Spuij
 * @since 1.4.0
 */
public class IntegerOpenClosedTypeConverter extends
		ZWaveStateConverter<Integer, OpenClosedType> {
	private int notOpenValue = 0x00;

	/**
	 * Default constructor which retains pre 1.8 behavior of
	 * <code>value != 0x00 ? OpenClosedType.OPEN</code>
	 * @author Dave Badia
	 * @since 1.8
	 */
	public IntegerOpenClosedTypeConverter() {
		super();
	}

	/**
	 * constructor which allows overriding of default behavior
	 * required for {@link ZWaveDoorLockConverter}
	 * @author Dave Badia
	 * @since 1.8
	 */
	public IntegerOpenClosedTypeConverter(int notOpenValue) {
		super();
		this.notOpenValue = notOpenValue;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected OpenClosedType convert(Integer value) {
		return value != notOpenValue ? OpenClosedType.OPEN : OpenClosedType.CLOSED;
	}

}
