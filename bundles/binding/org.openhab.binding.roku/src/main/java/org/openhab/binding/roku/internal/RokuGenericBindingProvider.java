/**
 * Copyright (c) 2010-2016 by the respective copyright holders.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.roku.internal;

import org.openhab.binding.roku.RokuBindingProvider;
import org.openhab.core.binding.BindingConfig;
import org.openhab.core.items.Item;
import org.openhab.core.library.items.ContactItem;
import org.openhab.core.library.items.DateTimeItem;
import org.openhab.core.library.items.NumberItem;
import org.openhab.core.library.items.SwitchItem;
import org.openhab.model.item.binding.AbstractGenericBindingProvider;
import org.openhab.model.item.binding.BindingConfigParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is responsible for parsing the binding configuration.
 *
 * @author Hans-Jörg Merk
 * @since 1.6.0
 */
public class RokuGenericBindingProvider extends AbstractGenericBindingProvider implements RokuBindingProvider {

    static final Logger logger = LoggerFactory.getLogger(RokuGenericBindingProvider.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public String getBindingType() {
        return "Roku";
    }

    /**
     * @{inheritDoc}
     */
    @Override
    public void validateItemType(Item item, String bindingConfig) throws BindingConfigParseException {
        if (!(item instanceof ContactItem || item instanceof NumberItem || item instanceof SwitchItem
                || item instanceof DateTimeItem)) {
            throw new BindingConfigParseException("item '" + item.getName() + "' is of type '"
                    + item.getClass().getSimpleName()
                    + "', only DateTime-, Contact-, Number- and SwitchItems are allowed - please check your *.items configuration");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void processBindingConfiguration(String context, Item item, String bindingConfig)
            throws BindingConfigParseException {
        super.processBindingConfiguration(context, item, bindingConfig);
        try {
            if (bindingConfig != null) {

                RokuBindingConfig config = new RokuBindingConfig();

                item.getName();

                String[] configParts = bindingConfig.split(";");
                if (configParts.length > 2) {
                    throw new BindingConfigParseException(
                            "Roku binding configuration must not have more than two parts");
                }

                config.udn = configParts[0];
                config.channelType = configParts.length < 2 ? RokuChannelType.state
                        : RokuChannelType.valueOf(configParts[1]);
                logger.debug("Configuration for Roku item '{}':", item.getName());
                logger.debug("        UDN = '{}'", config.udn);
                logger.debug("channelType = '{}'", config.channelType);

                addBindingConfig(item, config);

            } else {
                logger.warn("bindingConfig is NULL (item=" + item + ") -> processing bindingConfig aborted!");
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            logger.warn("bindingConfig is invalid (item=" + item + ") -> processing bindingConfig aborted!");
        }

    }

    /**
     * This is an internal data structure to store information from the binding
     * config strings and use it to answer the requests to the Roku binding
     * provider.
     */
    static private class RokuBindingConfig implements BindingConfig {
        public String udn;
        public RokuChannelType channelType;
    }

    /**
     * Return the friendlyName for the given <code>itemName</code>.
     * 
     * @param itemName
     *            the itemName to return the corresponding Roku friendlyName
     */
    @Override
    public String getUDN(String itemName) {
        RokuBindingConfig config = (RokuBindingConfig) bindingConfigs.get(itemName);
        return config != null ? config.udn : null;
    }

    /**
     * Return the specified channel type for the given <code>itemName</code> if specified, <code>null</code> otherwise.
     * 
     * @param itemName
     *            the itemName to return the channel type specified
     */
    @Override
    public RokuChannelType getChannelType(String itemName) {
        RokuBindingConfig config = (RokuBindingConfig) bindingConfigs.get(itemName);
        return config != null ? config.channelType : null;
    }

    /**
     * The channel type of the Roku item.
     * <ul>
     * <li>state</li>
     * <li>currentPower</li>
     * <li>lastOnFor</li>
     * <li>onToday</li>
     * <li>onTotal</li>
     * </ul>
     */
    public enum RokuChannelType {
        state,
        lastChangedAt,
        lastOnFor,
        onToday,
        onTotal,
        timespan,
        averagePower,
        currentPower,
        energyToday,
        energyTotal,
        standbyLimit
    }

}
