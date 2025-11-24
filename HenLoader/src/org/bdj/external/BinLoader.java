package org.bdj.external;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.File;
import java.io.FileInputStream;

import org.bdj.api.*;

public class BinLoader {
    // Memory mapping constants
    private static final int PROT_READ = 0x1;
    private static final int PROT_WRITE = 0x2;
    private static final int PROT_EXEC = 0x4;
    private static final int MAP_PRIVATE = 0x2;
    private static final int MAP_ANONYMOUS = 0x1000;
    
    // ELF constants
    private static final int ELF_MAGIC = 0x464c457f; // 0x7F 'E' 'L' 'F' in little endian
    private static final int PT_LOAD = 1;
    private static final int PAGE_SIZE = 0x1000;
    private static final int MAX_PAYLOAD_SIZE = 4 * 1024 * 1024; // 4MB
    
    private static final int READ_CHUNK_SIZE = 4096;
    
    private static final String USBPAYLOAD_RESOURCE = "/disc/BDMV/AUXDATA/aiofix_USBpayload.elf";
    
    private static API api;
    private static byte[] binData;
    private static long mmapBase;
    private static long mmapSize;
    private static long entryPoint;
    private static Thread payloadThread;

    static {
        try {
            api = API.getInstance();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static void start() {
        Thread startThread = new Thread(new Runnable() {
            public void run() {
                startInternal();
            }
        });
        startThread.setName("BinLoader");
        startThread.start();
    }
    
    private static void startInternal() {
        executeEmbeddedPayload();
    }
    
    private static void executeEmbeddedPayload() {
        try {
            File payload = new File(USBPAYLOAD_RESOURCE);
            FileInputStream fi = new FileInputStream(payload);
            byte[] bytes = new byte[fi.available()];
            fi.read(bytes);
            fi.close();
            loadFromData(bytes);
            run();
            waitForPayloadToExit();

        } catch (Exception e) {

        }
    }
    
    private static byte[] loadResourcePayload(String resourcePath) throws Exception {
        InputStream inputStream = BinLoader.class.getResourceAsStream(resourcePath);
        if (inputStream == null) {
            throw new RuntimeException("Resource not found: " + resourcePath);
        }
        
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[READ_CHUNK_SIZE];
        int bytesRead;
        int totalRead = 0;
        
        try {
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
                totalRead += bytesRead;
                
                // Safety check to prevent excessive resource loading
                if (totalRead > MAX_PAYLOAD_SIZE) {
                    throw new RuntimeException("Resource payload exceeds maximum size: " + MAX_PAYLOAD_SIZE);
                }
            }
            
            return outputStream.toByteArray();
            
        } finally {
            inputStream.close();
            outputStream.close();
        }
    }
    
    public static void loadFromData(byte[] data) throws Exception {
        if (data == null) {
            throw new IllegalArgumentException("Payload data cannot be null");
        }
        
        if (data.length == 0) {
            throw new IllegalArgumentException("Payload data cannot be empty");
        }
        
        if (data.length > MAX_PAYLOAD_SIZE) {
            throw new IllegalArgumentException("Payload too large: " + data.length + " bytes (max: " + MAX_PAYLOAD_SIZE + ")");
        }
        
        binData = data;
        
        // Round up to page boundary with overflow check
        long mmapSizeCalc;
        try {
            mmapSizeCalc = roundUp(data.length, PAGE_SIZE);
            if (mmapSizeCalc <= 0 || mmapSizeCalc > MAX_PAYLOAD_SIZE * 2) {
                throw new RuntimeException("Invalid mmap size calculation: " + mmapSizeCalc);
            }
        } catch (ArithmeticException e) {
            throw new RuntimeException("Integer overflow in mmap size calculation");
        }
        
        // Allocate executable memory
        int protFlags = PROT_READ | PROT_WRITE | PROT_EXEC;
        int mapFlags = MAP_PRIVATE | MAP_ANONYMOUS;
        
        long ret = Helper.syscall(Helper.SYS_MMAP, 0L, mmapSizeCalc, (long)protFlags, (long)mapFlags, -1L, 0L);
        if (ret < 0) {
            int errno = api.errno();
            throw new RuntimeException("mmap() failed with error: " + ret + " (errno: " + errno + ")");
        }
        
        // Validate mmap returned a reasonable address
        if (ret == 0 || ret == -1) {
            throw new RuntimeException("mmap() returned invalid address: 0x" + Long.toHexString(ret));
        }
        
        mmapBase = ret;
        mmapSize = mmapSizeCalc;
        
        
        try {
            // Check if ELF by reading magic bytes
            if (data.length >= 4) {
                int magic = ((data[3] & 0xFF) << 24) | ((data[2] & 0xFF) << 16) | 
                           ((data[1] & 0xFF) << 8) | (data[0] & 0xFF);
                
                if (magic == ELF_MAGIC) {
                    entryPoint = loadElfSegments(data);
                } else {
                    // Copy raw data to allocated memory with bounds checking
                    if (data.length > mmapSize) {
                        throw new RuntimeException("Payload size exceeds allocated memory");
                    }
                    api.memcpy(mmapBase, data, data.length);
                    entryPoint = mmapBase;
                }
            } else {
                throw new RuntimeException("Payload too small (< 4 bytes)");
            }
            
            // Validate entry point
            if (entryPoint == 0) {
                throw new RuntimeException("Invalid entry point: 0x0");
            }
            if (entryPoint < mmapBase || entryPoint >= mmapBase + mmapSize) {
                throw new RuntimeException("Entry point outside allocated memory range: 0x" + Long.toHexString(entryPoint));
            }
            
            
        } catch (Exception e) {
            // Cleanup on failure
            long munmapResult = Helper.syscall(Helper.SYS_MUNMAP, mmapBase, mmapSize);
            if (munmapResult < 0) {
            }
            mmapBase = 0;
            mmapSize = 0;
            entryPoint = 0;
            throw e;
        }
    }
    
    private static long loadElfSegments(byte[] data) throws Exception {
        // Create temporary buffer for ELF parsing to avoid header corruption
        long tempBuf = Helper.syscall(Helper.SYS_MMAP, 0L, (long)data.length,
                                      (long)(PROT_READ | PROT_WRITE), (long)(MAP_PRIVATE | MAP_ANONYMOUS), -1L, 0L);
        if (tempBuf < 0) {
            throw new RuntimeException("Failed to allocate temp buffer for ELF parsing");
        }
        
        try {
            // Copy data to temp buffer for parsing
            api.memcpy(tempBuf, data, data.length);
            
            // Read ELF header from temp buffer
            ElfHeader elfHeader = readElfHeader(tempBuf);
            
            // Load program segments directly to final locations
            for (int i = 0; i < elfHeader.phNum; i++) {
                long phdrAddr = tempBuf + elfHeader.phOff + (i * elfHeader.phEntSize);
                ProgramHeader phdr = readProgramHeader(phdrAddr);
                
                if (phdr.type == PT_LOAD && phdr.memSize > 0) {
                    // Calculate segment address (use relative offset)
                    long segAddr = mmapBase + (phdr.vAddr % 0x1000000);
                    
                    // Copy segment data from original data array
                    if (phdr.fileSize > 0) {
                        byte[] segmentData = new byte[(int)phdr.fileSize];
                        System.arraycopy(data, (int)phdr.offset, segmentData, 0, (int)phdr.fileSize);
                        api.memcpy(segAddr, segmentData, segmentData.length);
                    }
                    
                    // Zero out BSS section
                    if (phdr.memSize > phdr.fileSize) {
                        api.memset(segAddr + phdr.fileSize, 0, phdr.memSize - phdr.fileSize);
                    }
                }
            }
            
            return mmapBase + (elfHeader.entry % 0x1000000);
            
        } finally {
            // Clean up temp buffer
            Helper.syscall(Helper.SYS_MUNMAP, tempBuf, (long)data.length);
        }
    }
    
    public static void run() throws Exception {
        // Create Java thread to execute the payload
        payloadThread = new Thread(new Runnable() {
            public void run() {
                try {
                    // Call the entry point function
                    long result = api.call(entryPoint);
                    
                } catch (Exception e) {
                }
            }
        });
        
        payloadThread.setName("BinPayload");
        payloadThread.start();
        
    }
    
    public static void waitForPayloadToExit() throws Exception {
        if (payloadThread != null) {
            try {
                payloadThread.join(); // Wait for thread to finish
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // Restore interrupt status
            }
        }
        
        // Cleanup allocated memory with validation
        if (mmapBase != 0 && mmapSize > 0) {

            try {
                long ret = Helper.syscall(Helper.SYS_MUNMAP, mmapBase, mmapSize);
                if (ret < 0) {
                    int errno = api.errno();
                } else {
                }
            } catch (Exception e) {
            }
            
            // Clear variables to prevent reuse
            mmapBase = 0;
            mmapSize = 0;
            entryPoint = 0;
            binData = null;
        } else {
            
        }
        
        // Clear thread reference
        payloadThread = null;
        
    }
    
    private static class ElfHeader {
        long entry;
        long phOff;
        int phEntSize;
        int phNum;
    }
    
    private static class ProgramHeader {
        int type;
        long offset;
        long vAddr;
        long fileSize;
        long memSize;
    }
    
    private static ElfHeader readElfHeader(long addr) {
        ElfHeader header = new ElfHeader();
        header.entry = api.read64(addr + 0x18);
        header.phOff = api.read64(addr + 0x20);
        header.phEntSize = api.read16(addr + 0x36) & 0xFFFF;
        header.phNum = api.read16(addr + 0x38) & 0xFFFF;
        return header;
    }
    
    private static ProgramHeader readProgramHeader(long addr) {
        ProgramHeader phdr = new ProgramHeader();
        phdr.type = api.read32(addr + 0x00);
        phdr.offset = api.read64(addr + 0x08);
        phdr.vAddr = api.read64(addr + 0x10);
        phdr.fileSize = api.read64(addr + 0x20);
        phdr.memSize = api.read64(addr + 0x28);
        return phdr;
    }
    
    private static long roundUp(long value, long boundary) {
        if (value < 0 || boundary <= 0) {
            throw new IllegalArgumentException("Invalid arguments: value=" + value + ", boundary=" + boundary);
        }
        
        // Check for potential overflow
        if (value > Long.MAX_VALUE - boundary) {
            throw new ArithmeticException("Integer overflow in roundUp calculation");
        }
        
        return ((value + boundary - 1) / boundary) * boundary;
    }
}