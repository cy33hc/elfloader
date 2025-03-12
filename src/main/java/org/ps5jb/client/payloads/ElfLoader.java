package org.ps5jb.client.payloads;

import org.ps5jb.client.payloads.constants.ELF;
import org.ps5jb.client.payloads.constants.MEM;
import org.ps5jb.client.payloads.lib.LibKernelExtended;
import org.ps5jb.client.payloads.lib.LibcInternal;
import org.ps5jb.client.payloads.parser.ElfParser;
import org.ps5jb.client.payloads.parser.ElfProgramHeader;
import org.ps5jb.client.payloads.parser.ElfRelocation;
import org.ps5jb.client.payloads.parser.ElfSectionHeader;
import org.ps5jb.client.utils.init.KernelReadWriteUnavailableException;
import org.ps5jb.client.utils.init.SdkInit;
import org.ps5jb.client.utils.memory.MemoryDumper;
import org.ps5jb.client.utils.process.ProcessUtils;
import org.ps5jb.client.utils.stdio.StdioReaderThread;
import org.ps5jb.loader.KernelAccessor;
import org.ps5jb.loader.KernelReadWrite;
import org.ps5jb.loader.Status;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.SdkSoftwareVersionUnsupportedException;
import org.ps5jb.sdk.core.kernel.KernelAccessorIPv6;
import org.ps5jb.sdk.core.kernel.KernelOffsets;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.include.sys.proc.Process;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ElfLoader implements Runnable {

    private final LibKernelExtended libKernel = new LibKernelExtended();
    private ProcessUtils procUtils;
    private SdkInit sdk;

    private static final boolean VERBOSE = false;
    String elf_name = "elfldr.elf";

    private boolean init() {
        try {
            sdk = SdkInit.init(true, false);
            procUtils = new ProcessUtils(libKernel);
        } catch (KernelReadWriteUnavailableException e) {
            println("Kernel R/W is not available, aborting");
            libKernel.closeLibrary();
            return false;
        } catch (SdkSoftwareVersionUnsupportedException e) {
            Status.printStackTrace("Unsupported firmware version: ", e);
            libKernel.closeLibrary();
            return false;
        }

        return true;
    }

    @Override
    public void run() {
        if (!init()) {
            return;
        }

        byte[] elf_bytes;
        try {
            // Read the ELF file from Jar
            InputStream inputStream = this.getClass().getResourceAsStream("/" + elf_name);
            if (inputStream != null) {
                elf_bytes = new byte[inputStream.available()];
                DataInputStream dataInputStream = new DataInputStream(inputStream);
                dataInputStream.readFully(elf_bytes);

                for (int i = 0; i < 4; i++) {
                    if (elf_bytes[i] != ELF.elfMagic[i]) {
                        println("[!] " + elf_name + " not valid. Aborting.");
                        return;
                    }
                }
            } else {
                println("[!] " + elf_name + " not found in JAR");
                return;
            }
        } catch (IOException e) {
            Status.printStackTrace("Error while reading " + elf_name, e);
            libKernel.closeLibrary();
            return;
        }

        // Apply process patch
        Process curProc = new Process(KernelPointer.valueOf(sdk.curProcAddress));
        patchProcess(curProc);
        println("[+] Patch applied to " + curProc.getName());

        // Enable debug settings
        if (enableDebug()) {
            println("[+] Debug settings enabled");
        } else {
            println("[-] Debug settings already enabled");
        }

        // Allocate memory for ELF
        int elf_store_size = elf_bytes.length;
        Pointer elf_store = Pointer.malloc(elf_store_size);

        // Store ELF into memory
        for (int i = 0; i < elf_store_size; i++) {
            elf_store.write1(i, elf_bytes[i]);
        }

        String with_addr = VERBOSE ? " at 0x" + Long.toHexString(elf_store.addr()) : "";
        println("[+] Stored " + elf_name + with_addr + " (" + elf_bytes.length + " bytes)");

        println("Prepare ELF execution...");

        println("---------------------------------------------------------------------------", true);
        println("Memory mapping:", true);
        println("---------------------------------------------------------------------------", true);

        ElfParser elf = new ElfParser(elf_bytes);

        short flags = MEM.MAP_PRIVATE | MEM.MAP_ANONYMOUS;
        byte prot = MEM.PROT_READ | MEM.PROT_WRITE;
        long baseAddr;
        if (elf.getElfType() == ELF.ET_DYN) {
            baseAddr = 0;
        } else if (elf.getElfType() == ELF.ET_EXEC) {
            baseAddr = elf.getMinVaddr();
            flags |= MEM.MAP_FIXED;
        } else {
            Status.println("  [!] ELF type not supported");
            return;
        }

        Pointer mmap_ret = libKernel.mmap(Pointer.valueOf(baseAddr), elf.getElfSize(), prot, flags, -1, 0);

        if (mmap_ret.addr() == -1) {
            println("  [!] Could not map anonymous memory");
            return;
        } else {
            Status.println("  [+] Mapped memory for ELF segments");
        }

        // Copy loadable segments
        Pointer elf_dest = mmap_ret;
        ElfProgramHeader[] pHeaders = elf.getProgramHeadersByType(ELF.PT_LOAD);
        for (ElfProgramHeader ph : pHeaders) {
            Pointer dest = elf_dest.inc(ph.getVaddr());
            copySegment(elf_store, dest, ph.getMemsz(), ph.getFilesz(), ph.getOffset());

            Status.println("  [+] ELF segment copied into memory");
            println("Segment copied into memory @ 0x"
                    + Long.toHexString(dest.addr()) + " ("
                    + ph.getMemsz() + " bytes)", true);

            println("test read data @ RW dest: 0x" + Long.toHexString(dest.read8()), true);
        }

        println("---------------------------------------------------------------------------", true);
        println("Relocations:", true);
        println("---------------------------------------------------------------------------", true);

        int countRel = 0;

        // Apply relocations
        ElfSectionHeader[] sHeaders = elf.getSectionHeadersByType(ELF.SHT_RELA);
        for (ElfSectionHeader sh : sHeaders) {
            for (ElfRelocation r : sh.getRelocations()) {
                if (r.getType() == ELF.R_X86_64_RELATIVE) {
                    Pointer reloc_addr = elf_dest.inc(r.getOffset());
                    long reloc_val = elf_dest.addr() + r.getAddend();
                    reloc_addr.write8(reloc_val);
                    countRel++;
                }
            }
        }

        Status.println("  [+] Applied relocations: " + countRel);

        // Set protection of segments
        for (ElfProgramHeader ph : pHeaders) {
            if (ph.getMemsz() > 0) {
                Pointer segmentAddr = elf_dest.inc(ph.getVaddr());
                long segmentSize = MEM.roundPage(ph.getMemsz());
                if ((ph.getFlags() & ELF.PF_X) == ELF.PF_X) {
                    byte memProt = MEM.translateProtection(ph.getFlags());
                    libKernel.kMprotect(curProc, segmentAddr, memProt);
                } else {
                    byte memProt = MEM.translateProtection(ph.getFlags());
                    libKernel.mprotect(segmentAddr, segmentSize, memProt);
                }
            }
        }

        Status.println("  [+] Set memory protection flags");

        // verify protection
        if (VERBOSE) {
            for (ElfProgramHeader ph : pHeaders) {
                if (ph.getMemsz() > 0) {
                    Pointer segmentAddr = elf_dest.inc(ph.getVaddr());
                    long segmentSize = MEM.roundPage(ph.getMemsz());
                    libKernel.printProtection(curProc, segmentAddr);
                }
            }
        }

        //
        // ELF Arguments
        //
        Pointer rwpair_mem = Pointer.malloc(8);
        Pointer payload_out = Pointer.malloc(8);
        Pointer args = Pointer.malloc(48); // 8 * 6

        // IPv6 Accessor
        KernelAccessorIPv6 ipv6;
        KernelAccessor ka = KernelReadWrite.getAccessor(getClass().getClassLoader());
        if (ka instanceof KernelAccessorIPv6) {
            ipv6 = (KernelAccessorIPv6) ka;
        } else {
            sdk.restoreNonAgcKernelReadWrite();
            ipv6 = (KernelAccessorIPv6) KernelReadWrite.getAccessor(getClass().getClassLoader());
        }

        // Pipe stuff
        Pointer rwpipe = Pointer.malloc(8);
        rwpipe.write4(ipv6.getPipeReadFd());
        rwpipe.write4(4, ipv6.getPipeWriteFd());

        // Pass master/victim pair to payload so it can do read/write
        rwpair_mem.write4(ipv6.getMasterSock());
        rwpair_mem.write4(4, ipv6.getVictimSock());

        Pointer dlsym = libKernel.addrOf("getpid");
//        Pointer dlsym = libKernel.addrOf("sceKernelDlsym");
        long kdata_addr = sdk.kernelDataAddress;

        println("---------------------------------------------------------------------------", true);
        println("ELF arguments:", true);
        println("---------------------------------------------------------------------------", true);
        println("dlsym addr:       0x" + Long.toHexString(dlsym.addr()), true);
        println("rwpipe addr:      0x" + Long.toHexString(rwpipe.addr()), true);
        println("rwpipe[0]:        0x" + Integer.toHexString(rwpipe.read4()), true);
        println("rwpipe[1]:        0x" + Integer.toHexString(rwpipe.read4(4)), true);
        println("rwpair addr:      0x" + Long.toHexString(rwpair_mem.addr()), true);
        println("rwpair[0]:        0x" + Integer.toHexString(rwpair_mem.read4()), true);
        println("rwpair[1]:        0x" + Integer.toHexString(rwpair_mem.read4(4)), true);
        println("ipv6 pipe addr:   0x" + Long.toHexString(ipv6.getPipeAddress().addr()), true);
        println("kdata addr:       0x" + Long.toHexString(kdata_addr), true);
        println("payload ret addr: 0x" + Long.toHexString(payload_out.addr()), true);

        args.inc(0x00).write8(dlsym.addr());                 // arg1 = dlsym_t* dlsym
        args.inc(0x08).write8(rwpipe.addr());                // arg2 = int *rwpipe[2]
        args.inc(0x10).write8(rwpair_mem.addr());            // arg3 = int *rwpair[2]
        args.inc(0x18).write8(ipv6.getPipeAddress().addr()); // arg4 = uint64_t kpipe_addr
        args.inc(0x20).write8(kdata_addr);                   // arg5 = uint64_t kdata_base_addr
        args.inc(0x28).write8(payload_out.addr());           // arg6 = int *payloadout

        Status.println("  [+] Prepared ELF arguments");

        println("---------------------------------------------------------------------------", true);
        println("ELF invocation:", true);
        println("---------------------------------------------------------------------------", true);


        Pointer elf_entry_point = Pointer.valueOf(elf_dest.addr() + elf.getElfEntry());

        println("mapping_addr:    0x" + Long.toHexString(elf_dest.addr()), true);
        println("elf_entry:       0x" + Long.toHexString(elf.getElfEntry()), true);
        println("elf_entry_point: 0x" + Long.toHexString(elf_entry_point.addr()), true);
        println("args addr:       0x" + Long.toHexString(args.addr()), true);


        println("Execution...");
        println("  [+] Starting " + elf_name);

        //
        // Java Thread
        //
        ElfRunner runner = new ElfRunner(elf_entry_point, args);
        Thread t = new Thread(runner);
        t.start();
        try {
            t.join();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        int retVal = runner.getReturnValue();

        println("  [+] Finished");
        println("Done.");

        println("payload out = 0x" + Long.toHexString(payload_out.read8()), true);
        println("return value = " + retVal, true);

        // Cleanup
        payload_out.free();
        rwpipe.free();
        rwpair_mem.free();
        args.free();
        elf_store.free();
        libKernel.munmap(elf_dest, elf.getElfSize());
    }

    private void patchProcess(Process process) {
        // Patch ucred
        procUtils.setUserGroup(process, new int[]{
                0, // cr_uid
                0, // cr_ruid
                0, // cr_svuid
                1, // cr_ngroups
                0  // cr_rgid
        });

        final long SYSTEM_AUTHID   = 0x4800000000010003l;
        final long COREDUMP_AUTHID = 0x4800000000000006l;
        final long DEVICE_AUTHID   = 0x4801000000000013l;

        // Escalate sony privs
        procUtils.setPrivs(process, new long[]{
                DEVICE_AUTHID,       // cr_sceAuthId
                0xFFFFFFFFFFFFFFFFL, // cr_sceCaps[0]
                0xFFFFFFFFFFFFFFFFL, // cr_sceCaps[1]
                0x80                 // cr_sceAttr[0]
        });

        // Remove dynlib restriction
        KernelPointer dynlibAddr = process.getDynLib();
        dynlibAddr.write4(0x118, 0);
        dynlibAddr.write8(0x18, 1);

        // Bypass libkernel address range check (credit @cheburek3000)
        dynlibAddr.write8(0xf0, 0);
        dynlibAddr.write8(0xf8, -1);
    }

    private boolean enableDebug() {
        boolean appliedPatch = false;
        KernelOffsets offsets = sdk.kernelOffsets;
        KernelPointer kdata = KernelPointer.valueOf(sdk.kernelDataAddress, false);

        // enable direct memory access
        sdk.switchToAgcKernelReadWrite(true);

        // Security flags
        KernelPointer secFlagsPtr = kdata.inc(offsets.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS);
        int secFlagsVal = secFlagsPtr.read4();
        if ((secFlagsVal & 0x14) != 0x14) {
            secFlagsPtr.write4(secFlagsVal | 0x14);
            appliedPatch = true;
        }

        // target ID
        KernelPointer targetIdPtr = kdata.inc(offsets.OFFSET_KERNEL_DATA_BASE_TARGET_ID);
        byte targetId = targetIdPtr.read1();
        if (targetId != (byte) 0x82) {
            targetIdPtr.write1((byte) 0x82);
            appliedPatch = true;
        }

        // QA flags
        KernelPointer qaFlagsPtr = kdata.inc(offsets.OFFSET_KERNEL_DATA_BASE_QA_FLAGS);
        long qaFlagsVal = qaFlagsPtr.read8();
        final long QA_MASK = 0x0000000000010300L;
        if ((qaFlagsVal & QA_MASK) != QA_MASK) {
            qaFlagsPtr.write8(qaFlagsVal | QA_MASK);
            appliedPatch = true;
        }

        // Utoken flag
        KernelPointer uTokenFlagsPtr = kdata.inc(offsets.OFFSET_KERNEL_DATA_BASE_UTOKEN_FLAGS);
        byte uTokenFlagsVal = uTokenFlagsPtr.read1();
        if ((uTokenFlagsVal & 0x1) != 0x1) {
            uTokenFlagsPtr.write1((byte) (uTokenFlagsVal | 0x1));
            appliedPatch = true;
        }

        // Notification: debug settings enabled
        if (appliedPatch) {
            libKernel.sceKernelSendNotificationRequest("Debug Settings enabled");
        }

        // disable DMA
        sdk.restoreNonAgcKernelReadWrite();

        return appliedPatch;
    }

    private void println(String message) {
        println(message, false);
    }

    private void println(String message, boolean verbose) {
        if (!verbose || VERBOSE) {
            Status.println(message);
        }
    }

    private void copySegment(Pointer src, Pointer dest, long memSize, long fileSize, long offset) {
        for (long i = 0; i < memSize; i += 8) {
            long src_qword = (i >= fileSize) ? 0 : src.read8(offset + i);
            dest.write8(i, src_qword);
        }
    }
}