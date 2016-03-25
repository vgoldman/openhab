/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.mpd.internal;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.openhab.binding.mpd.MpdBindingProvider;
import org.openhab.core.binding.BindingConfig;
import org.openhab.core.items.Item;
import org.openhab.core.library.items.DimmerItem;
import org.openhab.core.library.items.NumberItem;
import org.openhab.core.library.items.StringItem;
import org.openhab.core.library.items.SwitchItem;
import org.openhab.model.item.binding.AbstractGenericBindingProvider;
import org.openhab.model.item.binding.BindingConfigParseException;

/**
 * <p>
 * This class can parse information from the generic binding format and
 * provides MPD binding information from it. It registers as a
 * {@link MpdBindingProvider} service as well.
 * </p>
 *
 * <p>
 * Here are some examples for valid binding configuration strings:
 * <ul>
 * <li><code>{ mpd="ON:bath:play, OFF:bath:stop" }</code> - starts or stops playing the player named 'bath'</li>
 * <li><code>{ mpd="INCREASE:bath:volume_increase, DECREASE:bath:volume_decrease" }</code> - increases or decreases the
 * volume of the player named 'bath'</li>
 * </ul>
 *
 * @author Thomas.Eichstaedt-Engelen
 * @author Matthew Bowman
 *
 * @since 0.8.0
 */
public class MpdGenericBindingProvider extends AbstractGenericBindingProvider implements MpdBindingProvider {

    private static final String PARAM_SUFFIX = ":param";

    /**
     * {@inheritDoc}
     */
    @Override
    public String getBindingType() {
        return "mpd";
    }

    /**
     * @{inheritDoc}
     */
    @Override
    public void validateItemType(Item item, String bindingConfig) throws BindingConfigParseException {
        if (!(item instanceof SwitchItem || item instanceof DimmerItem || item instanceof StringItem
                || item instanceof NumberItem)) {
            throw new BindingConfigParseException(
                    "item '" + item.getName() + "' is of type '" + item.getClass().getSimpleName()
                            + "', only Switch- and DimmerItems are allowed - please check your *.items configuration");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void processBindingConfiguration(String context, Item item, String bindingConfig)
            throws BindingConfigParseException {

        super.processBindingConfiguration(context, item, bindingConfig);

        MpdBindingConfig config = new MpdBindingConfig();
        parseBindingConfig(bindingConfig, config);
        addBindingConfig(item, config);
    }

    protected void parseBindingConfig(String bindingConfigs, MpdBindingConfig config)
            throws BindingConfigParseException {

        String bindingConfig = StringUtils.substringBefore(bindingConfigs, ",");
        String bindingConfigTail = StringUtils.substringAfter(bindingConfigs, ",");

        String[] configParts = bindingConfig.split(":");
        if (configParts.length != 3) {
            throw new BindingConfigParseException(
                    "MPD binding configuration must consist of three parts [config=" + configParts + "]");
        }

        String command = StringUtils.trim(configParts[0]);
        String playerId = StringUtils.trim(configParts[1]);
        String playerCommand = StringUtils.trim(configParts[2]);
        // check for optional command=param binding
        String[] playerCommandParts = playerCommand.split("=");
        if (playerCommandParts.length == 2) {
            // rewrite command=param -> command
            playerCommand = StringUtils.trim(playerCommandParts[0]);
            String playerCommandParam = StringUtils.trim(playerCommandParts[1]);
            // save the param in the config
            config.put(command + PARAM_SUFFIX, playerCommandParam);
        }

        // if there are more commands to parse do that recursively ...
        if (StringUtils.isNotBlank(bindingConfigTail)) {
            parseBindingConfig(bindingConfigTail, config);
        }

        config.put(command, playerId + ":" + playerCommand);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getPlayerCommand(String itemName, String command) {
        MpdBindingConfig config = (MpdBindingConfig) bindingConfigs.get(itemName);
        return config != null ? config.get(command) : null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getPlayerCommandParam(String itemName, String command) {
        MpdBindingConfig config = (MpdBindingConfig) bindingConfigs.get(itemName);
        return config != null ? config.get(command + PARAM_SUFFIX) : null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String[] getItemNamesByPlayerAndPlayerCommand(String playerId, PlayerCommandTypeMapping playerCommand) {
        Set<String> itemNames = new HashSet<String>();
        for (String itemName : bindingConfigs.keySet()) {
            MpdBindingConfig mpdConfig = (MpdBindingConfig) bindingConfigs.get(itemName);
            if (mpdConfig.containsKey("PERCENT") && PlayerCommandTypeMapping.VOLUME.equals(playerCommand)) {
                itemNames.add(itemName);
            } else if (mpdConfig.containsKey("TITLE") && PlayerCommandTypeMapping.TRACKINFO.equals(playerCommand)) {
                itemNames.add(itemName);
            } else if (mpdConfig.containsKey("ARTIST") && PlayerCommandTypeMapping.TRACKARTIST.equals(playerCommand)) {
                itemNames.add(itemName);
            } else if (mpdConfig.containsKey(playerCommand.type.toString())) {
                // we check to make sure the binding config contains
                // playerId:playerCommand otherwise we get extra items
                String actual = mpdConfig.get(playerCommand.type.toString());
                String expected = playerId + ":" + playerCommand.toString().toLowerCase();
                if (StringUtils.equals(actual, expected)) {
                    itemNames.add(itemName);
                }
            }
        }
        return itemNames.toArray(new String[itemNames.size()]);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String[] getItemNamesByPlayerOutputCommand(String playerId, PlayerCommandTypeMapping command, int outputId) {
        Set<String> itemNames = new HashSet<String>();
        for (String itemName : bindingConfigs.keySet()) {
            MpdBindingConfig config = (MpdBindingConfig) bindingConfigs.get(itemName);
            // We're looking for either...
            // ---
            // ON = <player-id>:enable
            // ON:param = <output-id>
            // --- or ---
            // OFF = <player-id>:disable
            // OFF:param = <output-id>
            // ---
            String k1 = command.type.toString();
            String v1 = playerId + ":" + command.toString().toLowerCase();
            String k2 = command.type.toString() + PARAM_SUFFIX;
            String v2 = String.valueOf(outputId);
            if (StringUtils.equals(config.get(k1), v1) && StringUtils.equals(config.get(k2), v2)) {
                itemNames.add(itemName);
            }
        }
        return itemNames.toArray(new String[itemNames.size()]);
    }

    /**
     * This is an internal data structure to store information from the binding
     * config strings and use it to answer the requests to the MPD binding
     * provider.
     */
    static class MpdBindingConfig extends HashMap<String, String>implements BindingConfig {

        /** generated serialVersion UID */
        private static final long serialVersionUID = 6164971643530954095L;

    }

}
