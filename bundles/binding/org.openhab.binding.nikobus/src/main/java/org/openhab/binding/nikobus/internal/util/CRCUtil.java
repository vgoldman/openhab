/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.nikobus.internal.util;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang.StringUtils;

/**
 * Utility to calculate a Nikobus checksums.
 *
 * @author Davy Vanherbergen
 * @since 1.3.0
 */
public class CRCUtil {

    private static final int CRC_INIT = 0xFFFF;

    private static final int POLYNOMIAL = 0x1021;

    /**
     * Calculate the CRC16-CCITT checksum on the input string and return the
     * input string with the checksum appended.
     * 
     * @param input
     *            String representing hex numbers.
     * @return input string + CRC.
     */
    public static String appendCRC(String input) {

        if (input == null) {
            return null;
        }

        int check = CRC_INIT;

        for (byte b : DatatypeConverter.parseHexBinary(input)) {
            for (int i = 0; i < 8; i++) {
                if (((b >> (7 - i) & 1) == 1) ^ ((check >> 15 & 1) == 1)) {
                    check = check << 1;
                    check = check ^ POLYNOMIAL;
                } else {
                    check = check << 1;
                }
            }
        }
        check = check & CRC_INIT;
        String checksum = StringUtils.leftPad(Integer.toHexString(check), 4, "0");
        return (input + checksum).toUpperCase();
    }

    /**
     * Calculate the second checksum on the input string and return the
     * input string with the checksum appended.
     * 
     * @param input
     *            String representing a nikobus command.
     * @return input string + CRC.
     */
    public static String appendCRC2(String input) {

        int check = 0;

        for (byte b : input.getBytes()) {

            check = check ^ b;

            for (int i = 0; i < 8; i++) {

                if (((check & 0xff) >> 7) != 0) {
                    check = check << 1;
                    check = check ^ 0x99;
                } else {
                    check = check << 1;
                }
                check = check & 0xff;
            }

        }
        return input + StringUtils.leftPad(Integer.toHexString(check), 2, "0").toUpperCase();

    }

}
