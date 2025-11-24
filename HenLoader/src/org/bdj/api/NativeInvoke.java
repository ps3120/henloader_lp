package org.bdj.api;

import org.bdj.api.API;
import org.bdj.api.Buffer;

public class NativeInvoke {
    static API api;
    static long sceKernelSendNotificationRequestAddr;

    static {
        try {
            api = API.getInstance();
            sceKernelSendNotificationRequestAddr = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, "sceKernelSendNotificationRequest");
        } catch (Exception e) {

        }
    }

    public static int sendNotificationRequest(String msg) {
        if (sceKernelSendNotificationRequestAddr == 0) {
            return -1;
        }
        
        long size = 0xc30;
        Buffer buffer = new Buffer((int)size);

        buffer.fill((byte)0);
        buffer.putInt(0x10, -1);
        
        byte[] msgBytes = msg.getBytes();
        for (int i = 0; i < msgBytes.length && i < (size - 0x2d - 1); i++) {
            buffer.putByte(0x2d + i, msgBytes[i]);
        }

        buffer.putByte(0x2d + Math.min(msgBytes.length, (int)(size - 0x2d - 1)), (byte)0);
        
        long res = api.call(sceKernelSendNotificationRequestAddr, 0, buffer.address(), size, 0);
        
        return (int)res;
    }
}