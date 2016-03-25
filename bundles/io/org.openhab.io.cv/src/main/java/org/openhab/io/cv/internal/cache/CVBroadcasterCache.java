/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.io.cv.internal.cache;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;

import org.atmosphere.cache.UUIDBroadcasterCache;
import org.atmosphere.cpr.BroadcasterCache;
import org.openhab.core.items.Item;
import org.openhab.io.cv.internal.resources.beans.ItemListBean;
import org.openhab.io.cv.internal.resources.beans.ItemStateListBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An {@link BroadcasterCache} implementation based on
 * {@link UUIDBroadcasterCache} which aggregates the cached messages to one
 * single message containing all changed states.
 *
 * @author Tobias Bräutigam
 *
 * @since 1.4.0
 */
public class CVBroadcasterCache extends UUIDBroadcasterCache {

    private final static Logger logger = LoggerFactory.getLogger(CVBroadcasterCache.class);

    @Override
    public List<Object> retrieveFromCache(String broadcasterId, String uuid) {
        List<Object> result = new ArrayList<Object>();
        ItemStateListBean response = new ItemStateListBean(new ItemListBean());
        for (Object cacheMessage : super.retrieveFromCache(broadcasterId, uuid)) {
            if (cacheMessage instanceof ItemStateListBean) {
                ItemStateListBean cachedStateList = (ItemStateListBean) cacheMessage;
                // add states to the response (maybe a comparison is needed here
                // so that only the last state of an item is used)
                for (JAXBElement elem : cachedStateList.stateList.entries) {
                    boolean exists = false;
                    for (JAXBElement responseElem : response.stateList.entries) {
                        if (responseElem.getName().equals(elem.getName())) {
                            // Element already exists in the response -> just update the state
                            responseElem.setValue(elem.getValue());
                            exists = true;
                            break;
                        }
                    }
                    if (!exists) {
                        // add element to response
                        response.stateList.entries.add(elem);
                    }
                }
                if (response.index < cachedStateList.index) {
                    response.index = cachedStateList.index;
                }
            } else if (cacheMessage instanceof Item) {
                Item item = (Item) cacheMessage;
                boolean exists = false;
                for (JAXBElement responseElem : response.stateList.entries) {
                    if (responseElem.getName().getLocalPart().equals(item.getName())) {
                        // Element already exists in the response -> just update the state
                        responseElem.setValue(item.getState().toString());
                        exists = true;
                        break;
                    }
                }
                if (!exists) {
                    response.stateList.entries
                            .add(new JAXBElement(new QName(item.getName()), String.class, item.getState().toString()));
                }
            }
        }
        if (response.stateList.entries.size() > 0) {
            if (response.index == 0) {
                response.index = System.currentTimeMillis();
            }
            result.add(response);
        }
        logger.trace("Retrieved for AtmosphereResource {} cached messages {}", uuid, response.stateList.entries);
        return result;
    }

}
