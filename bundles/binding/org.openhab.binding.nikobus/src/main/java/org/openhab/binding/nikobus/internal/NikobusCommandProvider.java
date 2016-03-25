/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.nikobus.internal;

import org.apache.commons.lang.StringUtils;
import org.eclipse.osgi.framework.console.CommandInterpreter;
import org.eclipse.osgi.framework.console.CommandProvider;
import org.openhab.binding.nikobus.internal.core.NikobusCommand;

/**
 * Command provider. Provides some commands to test the Nikobus connection.
 *
 * @author Davy Vanherbergen
 * @since 1.3.0
 */
public class NikobusCommandProvider implements CommandProvider {

    private NikobusBinding binding;

    /**
     * {@inheritDoc}
     * 
     * Display available nikobus commands.
     */
    @Override
    public String getHelp() {
        StringBuilder buffer = new StringBuilder();
        buffer.append("--- Nikobus Commands---\n");
        appendCommand(buffer, "nikobus status", "Show connection status");
        appendCommand(buffer, "nikobus connect", "Connect to nikobus");
        appendCommand(buffer, "nikobus send '<command>'", "Send command to nikobus");
        appendCommand(buffer, "nikobus help", "Print this text");
        return buffer.toString();
    }

    /**
     * Add a right padded command to the provided builder.
     * 
     * @param builder
     * @param command
     * @param description
     */
    private void appendCommand(StringBuilder builder, String command, String description) {
        builder.append("\t");
        builder.append(StringUtils.rightPad(command, 43));
        builder.append(" - ");
        builder.append(description);
        builder.append("\n");
    }

    /**
     * Nikobus command implementation.
     * 
     * @param intp
     *            commandInterpreter
     * 
     * @return null
     */
    public Object _nikobus(CommandInterpreter intp) {
        try {
            String cmd = intp.nextArgument();

            if (cmd.equals("help")) {
                intp.println(getHelp());
                return null;
            }

            if (cmd.equals("connect")) {
                binding.connect();
                return null;
            }

            if (cmd.equals("send")) {
                String data = intp.nextArgument();
                if (data != null && data.length() > 0) {
                    binding.sendCommand(new NikobusCommand(data));
                } else {
                    intp.println(
                            "Missing command argument. Enclose command in single quotes. E.g. nikobus send '#N0D4CE6'");
                    intp.print(getHelp());
                }
                return null;
            }

            if (cmd.equals("status")) {
                intp.println(binding.getConnectionStatus());
                return null;
            }

            String address = intp.nextArgument();
            if (address == null || address.length() != 4) {
                intp.println(getHelp());
                return null;
            } else {
                address = address.toUpperCase();
            }

            return null;

        } catch (Exception e) {
            intp.print(getHelp());
        }

        return null;
    }

    /**
     * Setter for DS.
     * 
     * @param binding
     */
    public void setBinding(NikobusBinding binding) {
        this.binding = binding;
    }

    /**
     * Unsetter for DS.
     * 
     * @param binding
     */
    public void unsetBinding(NikobusBinding binding) {
        this.binding = null;
    }

}
