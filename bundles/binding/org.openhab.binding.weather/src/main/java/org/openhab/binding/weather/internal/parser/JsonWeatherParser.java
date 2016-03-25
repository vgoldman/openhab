/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.weather.internal.parser;

import java.io.InputStream;

import org.openhab.binding.weather.internal.model.Weather;
import org.openhab.binding.weather.internal.utils.PropertyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

/**
 * Weather parser with JSON data in the InputStream.
 *
 * @author Gerhard Riegler
 * @since 1.6.0
 */
public class JsonWeatherParser extends AbstractWeatherParser {
    private static final Logger logger = LoggerFactory.getLogger(JsonWeatherParser.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void parseInto(InputStream is, Weather weather) throws Exception {
        JsonFactory jsonFactory = new JsonFactory();
        JsonParser jp = jsonFactory.createParser(is);

        jp.nextValue();
        handleToken(jp, null, weather);
        jp.close();

        super.parseInto(is, weather);
    }

    /**
     * Iterates through the JSON structure and collects weather data.
     */
    private void handleToken(JsonParser jp, String property, Weather weather) throws Exception {
        JsonToken token = jp.getCurrentToken();
        String prop = PropertyResolver.add(property, jp.getCurrentName());

        if (token.isStructStart()) {
            boolean isObject = token == JsonToken.START_OBJECT || token == JsonToken.END_OBJECT;

            Weather forecast = !isObject ? weather : startIfForecast(weather, prop);
            while (!jp.nextValue().isStructEnd()) {
                handleToken(jp, prop, forecast);
            }
            if (isObject) {
                endIfForecast(weather, forecast, prop);
            }
        } else if (token != null) {
            try {
                setValue(weather, prop, jp.getValueAsString());
            } catch (Exception ex) {
                logger.error("Error setting property '{}' with value '{}' ({})", prop, jp.getValueAsString(),
                        ex.getMessage());
            }
        }
    }

}
