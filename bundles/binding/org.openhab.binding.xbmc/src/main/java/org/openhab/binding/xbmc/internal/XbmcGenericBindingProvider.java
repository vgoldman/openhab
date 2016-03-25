/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.xbmc.internal;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.openhab.binding.xbmc.XbmcBindingProvider;
import org.openhab.core.binding.BindingConfig;
import org.openhab.core.items.Item;
import org.openhab.core.library.items.DimmerItem;
import org.openhab.core.library.items.StringItem;
import org.openhab.core.library.items.SwitchItem;
import org.openhab.model.item.binding.AbstractGenericBindingProvider;
import org.openhab.model.item.binding.BindingConfigParseException;

/**
 * This class is responsible for parsing the binding configuration.
 *
 * @author tlan, Ben Jones
 * @since 1.5.0
 */
public class XbmcGenericBindingProvider extends AbstractGenericBindingProvider implements XbmcBindingProvider {

    private static final Pattern CONFIG_PATTERN = Pattern.compile(".\\[(.*)\\|(.*)\\]");

    @Override
    public String getBindingType() {
        return "xbmc";
    }

    @Override
    public void validateItemType(Item item, String bindingConfig) throws BindingConfigParseException {
        if (!(item instanceof StringItem) && !(item instanceof SwitchItem) && !(item instanceof DimmerItem)) {
            throw new BindingConfigParseException("item '" + item.getName() + "' is of type '"
                    + item.getClass().getSimpleName() + "', but only String, Switch or Dimmer items are allowed.");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void processBindingConfiguration(String context, Item item, String bindingConfig)
            throws BindingConfigParseException {
        super.processBindingConfiguration(context, item, bindingConfig);

        if (bindingConfig.startsWith("<")) {
            XbmcBindingConfig config = parseIncomingBindingConfig(item, bindingConfig);
            addBindingConfig(item, config);
        } else if (bindingConfig.startsWith(">")) {
            XbmcBindingConfig config = parseOutgoingBindingConfig(item, bindingConfig);
            addBindingConfig(item, config);
        } else if (bindingConfig.startsWith("=")) {
            XbmcBindingConfig config = parseBidirectionalBindingConfig(item, bindingConfig);
            addBindingConfig(item, config);
        } else {
            throw new BindingConfigParseException("Item '" + item.getName() + "' does not start with <, > or =.");
        }
    }

    private XbmcBindingConfig parseBidirectionalBindingConfig(Item item, String bindingConfig)
            throws BindingConfigParseException {
        Matcher matcher = CONFIG_PATTERN.matcher(bindingConfig);

        if (!matcher.matches()) {
            throw new BindingConfigParseException("Config for item '" + item.getName() + "' could not be parsed.");
        }

        String xbmcInstance = matcher.group(1);
        String property = matcher.group(2);

        return new XbmcBindingConfig(xbmcInstance, property, true, true);
    }

    private XbmcBindingConfig parseIncomingBindingConfig(Item item, String bindingConfig)
            throws BindingConfigParseException {
        Matcher matcher = CONFIG_PATTERN.matcher(bindingConfig);

        if (!matcher.matches()) {
            throw new BindingConfigParseException("Config for item '" + item.getName() + "' could not be parsed.");
        }

        String xbmcInstance = matcher.group(1);
        String property = matcher.group(2);

        return new XbmcBindingConfig(xbmcInstance, property, true, false);
    }

    private XbmcBindingConfig parseOutgoingBindingConfig(Item item, String bindingConfig)
            throws BindingConfigParseException {
        Matcher matcher = CONFIG_PATTERN.matcher(bindingConfig);

        if (!matcher.matches()) {
            throw new BindingConfigParseException("Config for item '" + item.getName() + "' could not be parsed.");
        }

        String xbmcInstance = matcher.group(1);
        String property = matcher.group(2);

        return new XbmcBindingConfig(xbmcInstance, property, false, true);
    }

    @Override
    public String getXbmcInstance(String itemname) {
        XbmcBindingConfig bindingConfig = (XbmcBindingConfig) bindingConfigs.get(itemname);
        return bindingConfig.getXbmcInstance();
    }

    @Override
    public String getProperty(String itemname) {
        XbmcBindingConfig bindingConfig = (XbmcBindingConfig) bindingConfigs.get(itemname);
        return bindingConfig.getProperty();
    }

    @Override
    public boolean isInBound(String itemname) {
        XbmcBindingConfig bindingConfig = (XbmcBindingConfig) bindingConfigs.get(itemname);
        return bindingConfig != null ? bindingConfig.isInBound() : false;
    }

    @Override
    public boolean isOutBound(String itemname) {
        XbmcBindingConfig bindingConfig = (XbmcBindingConfig) bindingConfigs.get(itemname);
        return bindingConfig != null ? bindingConfig.isOutBound() : false;
    }

    class XbmcBindingConfig implements BindingConfig {

        private String xbmcInstance;
        private String property;
        private boolean inBound = false;
        private boolean outBound = false;

        public XbmcBindingConfig(String xbmcInstance, String property, boolean inBound) {
            this.xbmcInstance = xbmcInstance;
            this.property = property;
            this.inBound = inBound;
        }

        public XbmcBindingConfig(String xbmcInstance, String property, boolean inBound, boolean outBound) {
            this.xbmcInstance = xbmcInstance;
            this.property = property;
            this.inBound = inBound;
            this.outBound = outBound;
        }

        public String getXbmcInstance() {
            return xbmcInstance;
        }

        public String getProperty() {
            return property;
        }

        public boolean isInBound() {
            return inBound;
        }

        public boolean isOutBound() {
            return outBound;
        }
    }
}
