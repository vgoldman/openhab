/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.action.telegram.internal;

/**
 * This class is the model for a Telegram bot/chat, identified by chatId and
 * token
 *
 * @author Paolo Denti
 * @since 1.8.0
 *
 */
public class TelegramBot {

    private String chatId;
    private String token;

    public TelegramBot(String chatId, String token) {
        this.chatId = chatId;
        this.token = token;
    }

    public String getChatId() {
        return chatId;
    }

    public String getToken() {
        return token;
    }
}
