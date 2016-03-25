/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.homematic.internal.binrpc;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

/**
 * A BIN-RPC request for sending data to the Homematic server.
 *
 * @author Gerhard Riegler
 * @since 1.5.0
 */
public class BinRpcRequest {
    private byte data[];
    private int dataoffset;
    private String methodName;
    private Collection<Object> args = new ArrayList<Object>();

    /**
     * Creates a new request with the specified methodName.
     */
    public BinRpcRequest(String methodName) {
        this.methodName = methodName;
    }

    /**
     * Adds arguments to the method.
     */
    public void addArg(Object arg) {
        args.add(arg);
    }

    public String getMethodName() {
        return methodName;
    }

    /**
     * Generates the binrpc data.
     */
    public byte[] createMessage() {
        data = new byte[256];
        if (methodName != null) {
            addInt(methodName.length());
            addString(methodName);
            addInt(args.size());
        }

        addList(args);

        byte fullreq[] = new byte[dataoffset + 8];
        System.arraycopy(data, 0, fullreq, 8, dataoffset);
        fullreq[0] = 'B';
        fullreq[1] = 'i';
        fullreq[2] = 'n';
        addInt(dataoffset);
        System.arraycopy(data, dataoffset - 4, fullreq, 4, 4);
        return fullreq;
    }

    private void addByte(byte b) {
        if (dataoffset == data.length) {
            byte newdata[] = new byte[data.length * 2];
            System.arraycopy(data, 0, newdata, 0, data.length);
            data = newdata;
        }
        data[dataoffset++] = b;
    }

    private void addInt(int n) {
        byte d[] = BigInteger.valueOf(n).toByteArray();
        for (int c = 0; c < 4 - d.length; c++) {
            addByte(n < 0 ? (byte) 0xFF : (byte) 0);
        }
        for (byte s : d) {
            addByte(s);
        }
    }

    private void addDouble(double v) {
        double tmp = Math.abs(v);
        int exp = 0;
        if (tmp != 0 && tmp < 0.5) {
            while (tmp < 0.5) {
                tmp *= 2;
                exp--;
            }
        } else {
            while (tmp >= 1) {
                tmp /= 2;
                exp++;
            }
        }
        if (v < 0) {
            tmp *= -1;
        }
        int mantissa = (int) Math.round(tmp * 0x40000000);
        addInt(mantissa);
        addInt(exp);
    }

    private void addString(String s) {
        byte sd[];
        try {
            sd = s.getBytes("ISO-8859-1");
        } catch (UnsupportedEncodingException use) {
            // Really shouldn't happen, fall back silently to platform encoding
            sd = s.getBytes();
        }
        for (byte ch : sd) {
            addByte(ch);
        }
    }

    private void addList(Collection<?> args) {
        for (Object o : args) {
            if (o.getClass() == String.class) {
                addInt(3);
                String s = (String) o;
                addInt(s.length());
                addString(s);
            } else if (o.getClass() == Boolean.class) {
                addInt(2);
                addByte(((Boolean) o).booleanValue() ? (byte) 1 : (byte) 0);
            } else if (o.getClass() == Integer.class) {
                addInt(1);
                addInt(((Integer) o).intValue());
            } else if (o.getClass() == Double.class) {
                addInt(4);
                addDouble(((Double) o).doubleValue());
            } else if (o.getClass() == BigInteger.class) {
                addInt(4);
                addDouble(((BigInteger) o).doubleValue());
            } else if (o instanceof List<?>) {
                Collection<?> l = (Collection<?>) o;
                addInt(0x100);
                addInt(l.size());
                addList(l);
            } else if (o instanceof Map<?, ?>) {
                Map<?, ?> l = (Map<?, ?>) o;
                addInt(0x101);
                addInt(l.size());
                for (Map.Entry<?, ?> me : l.entrySet()) {
                    String key = (String) me.getKey();
                    addInt(key.length());
                    addString(key);
                    addList(Collections.singleton(me.getValue()));
                }
            }
        }
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE).append("methodName", methodName)
                .append("args", args.toArray()).toString();
    }
}
