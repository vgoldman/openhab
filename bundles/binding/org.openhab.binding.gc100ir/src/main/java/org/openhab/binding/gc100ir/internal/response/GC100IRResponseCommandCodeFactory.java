/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.gc100ir.internal.response;

/**
 * A singleton factory that produces GC100IRResponseCommandCode objects.
 *
 * @author Stephen Liang
 * @since 1.9.0
 *
 */
public enum GC100IRResponseCommandCodeFactory {
    // Provides a singleton instance
    INSTANCE;

    /**
     * Produces a {@link GC100IRCommand} given a commandString. This method will read the first section of the string,
     * separated by comma and then call the appropriate handler.
     *
     * @param commandString A command string provided by the GC100IR device
     * @return A command representing the response
     */
    public GC100IRCommand produce(String commandString) {
        String[] sections = commandString.split(",", 1);

        if (sections.length == 0) {
            throw new IllegalArgumentException("The command string " + commandString + " is not formatted correctly");
        }

        GC100IRCommandCode gc100IRCommandCode = GC100IRCommandCode.getCommandCodeFromString(sections[0]);

        switch (gc100IRCommandCode) {
            case COMPLETED_SUCCESSFULLY:
                return GC100IRCompleteResponseCommandCode.getResponseCommandCodeFromCommandString(commandString);
            case UNKNOWN_COMMAND:
                return GC100IRUnknownResponseCommandCode.getResponseCommandCodeFromCommandString(commandString);
            default:
                throw new IllegalArgumentException("Unknown command: " + gc100IRCommandCode);
        }
    }
}
