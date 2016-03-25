/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.samsungac.internal;

import org.openhab.core.types.Command;

/**
 * Enum values for the air conditioner to use.
 *
 * @author Stein Tore Tøsse
 * @since 1.6.0
 */
public enum CommandEnum {
    AC_FUN_OPMODE,
    AC_FUN_TEMPSET,
    AC_FUN_WINDLEVEL,
    AC_FUN_TEMPNOW,
    AC_FUN_POWER,
    AC_FUN_COMODE,
    AC_FUN_DIRECTION,
    AC_FUN_ENABLE,
    AC_FUN_SLEEP,
    AC_FUN_ERROR,
    AC_SG_VENDER01,
    AC_SG_VENDER02,
    AC_SG_VENDER03,
    AC_ADD2_VERSION,
    AC_SG_INTERNET,
    AC_SG_WIFI,
    AC_ADD_SPI,
    AC_ADD_STARTWPS,
    AC_ADD_APMODE_END,
    AC_ADD_AUTOCLEAN,
    AC_FUN_SUPPORTED,
    AC_ADD_SETKWH,
    AC_ADD_CLEAR_FILTER_ALARM,
    AC_OUTDOOR_TEMP,
    AC_COOL_CAPABILITY,
    AC_WARM_CAPABILITY,
    AC_ADD2_USEDWATT,
    AC_SG_MACHIGH,
    AC_SG_MACMID,
    AC_SG_MACLOW,
    AC_ADD2_PANEL_VERSION,
    AC_ADD2_OUT_VERSION,
    AC_FUN_MODEL,
    AC_ADD2_OPTIONCODE,
    AC_ADD2_USEDPOWER,
    AC_ADD2_USEDTIME,
    AC_ADD2_CLEAR_POWERTIME,
    AC_ADD2_FILTERTIME,
    AC_ADD2_FILTER_USE_TIME
}

enum ConvenientModeEnum {
    Off(0),
    Quiet(1),
    Sleep(2),
    Smart(3),
    SoftCool(4),
    TurboMode(5),
    WindMode1(6),
    WindMode2(7),
    WindMode3(8);
    protected int value;

    private ConvenientModeEnum(final int number) {
        value = number;
    }

    static ConvenientModeEnum getFromValue(Command value) {
        int val = Integer.valueOf(value.toString());
        for (ConvenientModeEnum en : ConvenientModeEnum.values()) {
            if (en.value == val) {
                return en;
            }
        }
        return ConvenientModeEnum.Off;
    }
}

enum DirectionEnum {
    Auto(0),
    SwingUD(1),
    Rotation(2),
    Fixed(3),
    SwingLR(4);
    int value;

    private DirectionEnum(int number) {
        value = number;
    }

    static DirectionEnum getFromValue(Command value) {
        int val = Integer.valueOf(value.toString());
        for (DirectionEnum en : DirectionEnum.values()) {
            if (en.value == val) {
                return en;
            }
        }
        return DirectionEnum.Auto;
    }
}

enum OperationModeEnum {
    Auto(0),
    Cool(1),
    Dry(2),
    Wind(3),
    Heat(4);
    int value;

    private OperationModeEnum(int number) {
        value = number;
    }

    static OperationModeEnum getFromValue(Command value) {
        int val = Integer.valueOf(value.toString());
        for (OperationModeEnum en : OperationModeEnum.values()) {
            if (en.value == val) {
                return en;
            }
        }
        return OperationModeEnum.Auto;
    }
}

enum OnOff {
    On("ON"),
    Off("OFF");
    String value;

    private OnOff(String val) {
        value = val;
    }
}

enum WindLevelEnum {
    Auto(0),
    Low(1),
    Mid(2),
    High(3),
    Turbo(4);
    int value;

    private WindLevelEnum(int val) {
        value = val;
    }

    static WindLevelEnum getFromValue(Command value) {
        int val = Integer.valueOf(value.toString());
        for (WindLevelEnum en : WindLevelEnum.values()) {
            if (en.value == val) {
                return en;
            }
        }
        return WindLevelEnum.Auto;
    }
}
