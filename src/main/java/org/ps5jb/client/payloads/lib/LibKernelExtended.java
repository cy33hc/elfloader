package org.ps5jb.client.payloads.lib;

import org.ps5jb.loader.Status;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.include.sys.mman.ProtectionFlag;
import org.ps5jb.sdk.include.sys.proc.Process;
import org.ps5jb.sdk.lib.LibKernel;

import java.util.Arrays;

public class LibKernelExtended extends LibKernel {
    private Pointer dup;
    private Pointer dup2;
    private Pointer pthread_join;
    private Pointer pthread_create_name_np;
    private Pointer sceKernelJitCreateAliasOfSharedMemory;
    private Pointer sceKernelJitCreateSharedMemory;
    private Pointer sceKernelDlsym;
    private final short OFFSET_VMROOT;

    public LibKernelExtended() {
        OFFSET_VMROOT = getOffsetVmRoot();
    }

    private short getOffsetVmRoot() {
        short offset;
        switch (getSystemSoftwareVersion()) {
            case 0x0100:
            case 0x0101:
            case 0x0102:
            case 0x0105:
            case 0x0110:
            case 0x0111:
            case 0x0112:
            case 0x0113:
            case 0x0114: {
                Status.println("[+] FW 1.xx detected");
                offset = 0x1C0;
                break;
            }
            case 0x0220:
            case 0x0225:
            case 0x0226:
            case 0x0230:
            case 0x0250:
            case 0x0270: {
                Status.println("[+] FW 2.xx detected");
                offset = 0x1C8;
                break;
            }
            case 0x0300:
            case 0x0310:
            case 0x0320:
            case 0x0321: {
                Status.println("[+] FW 3.xx detected");
                offset = 0x1C8;
                break;
            }
            case 0x0400:
            case 0x0402:
            case 0x0403:
            case 0x0450:
            case 0x0451: {
                Status.println("[+] FW 4.xx detected");
                offset = 0x1C8;
                break;
            }
            case 0x0500:
            case 0x0502:
            case 0x0510:
            case 0x0550: {
                Status.println("[+] FW 5.xx detected");
                offset = 0x1C8;
                break;
            }
            case 0x0600:
            case 0x0602:
            case 0x0650: {
                Status.println("[+] FW 6.xx detected");
                offset = 0x1D0;
                break;
            }
            case 0x0700:
            case 0x0701:
            case 0x0720:
            case 0x0740:
            case 0x0760:
            case 0x0761: {
                Status.println("[+] FW 7.xx detected");
                offset = 0x1D0;
                break;
            }
            default: {
                Status.println("[!] FW not supported");
                offset = 0;
            }
        }
        return offset;
    }

    public int dup(int fd) {
        if (dup == null) {
            dup = addrOf("dup");
        }
        return (int) call(dup, fd);
    }

    public int dup2(int oldfd, int newfd) {
        if (dup2 == null) {
            dup2 = addrOf("dup2");
        }
        return (int) call(dup2, oldfd, newfd);
    }

    public int pthread_create_name_np(Pointer thread, Pointer function, Pointer args, String name) {
        if (pthread_create_name_np == null) {
            pthread_create_name_np = addrOf("pthread_create_name_np");
        }
        short attr = 0; // use standard values
        Pointer buf = Pointer.fromString(name);
        try {
            return (int) call(pthread_create_name_np, thread.addr(), attr, function.addr(), args.addr(), buf.addr());
        } finally {
            buf.free();
        }
    }

    public int pthread_join(Pointer thread, Pointer returnVal) {
        if (pthread_join == null) {
            pthread_join = addrOf("pthread_join");
        }
        return (int) call(pthread_join, thread.addr(), returnVal.addr());
    }

    public int sceKernelJitCreateAliasOfSharedMemory(int fd, int maxProt, Pointer fdOut) {
        if (sceKernelJitCreateAliasOfSharedMemory == null) {
            sceKernelJitCreateAliasOfSharedMemory = addrOf("sceKernelJitCreateAliasOfSharedMemory");
        }
        return (int) call(sceKernelJitCreateAliasOfSharedMemory, fd, maxProt, fdOut.addr());
    }

    public int sceKernelJitCreateSharedMemory(long len, int maxProt, Pointer fdOut) {
        if (sceKernelJitCreateSharedMemory == null) {
            sceKernelJitCreateSharedMemory = addrOf("sceKernelJitCreateSharedMemory");
        }
        int name = 0; // use no name
        return (int) call(sceKernelJitCreateSharedMemory, name, len, maxProt, fdOut.addr());
    }

    public int sceKernelDlsym(String symbolName, Pointer addrOf) {
        if (sceKernelDlsym == null) {
            sceKernelDlsym = addrOf("sceKernelDlsym");
        }
        Pointer buf = Pointer.fromString(symbolName);
        try {
            return (int) call(sceKernelDlsym, 0x2001, buf.addr(), addrOf.addr());
        } finally {
            buf.free();
        }
    }

    public void printVmSpace(Process process) {
        KernelPointer vmRoot = process.getVmSpace().getPointer().pptr(OFFSET_VMROOT);
        Status.println("VmSpace binary tree: " + vmRoot);
        walkVmSpace(vmRoot);
    }

    private void walkVmSpace(KernelPointer entry) {
        if (!KernelPointer.NULL.equals(entry)) {
            long start = entry.read8(0x20);
            long end = entry.read8(0x28);
            int prot = entry.read1(0x64) & 0xFF;
            int maxprot = entry.read1(0x65) & 0xFF;
            Status.println("  Start: 0x" + Long.toHexString(start));
            Status.println("  End: 0x" + Long.toHexString(end));
            Status.println("  Prot: " + Arrays.asList(ProtectionFlag.valueOf(prot)));
            Status.println("  Max Prot: " + Arrays.asList(ProtectionFlag.valueOf(maxprot)));

            KernelPointer left = entry.pptr(0x10);
            walkVmSpace(left);

            KernelPointer right = entry.pptr(0x18);
            walkVmSpace(right);
        }
    }

    public void printProtection(Process proc, Pointer addr) {
        KernelPointer vmMapEntry = proc.getVmSpace().getPointer().pptr(OFFSET_VMROOT);
        while (!KernelPointer.NULL.equals(vmMapEntry)) {
            long start = vmMapEntry.read8(0x20);
            long end = vmMapEntry.read8(0x28);
            if (addr.addr() < start) {
                // go left in tree
                vmMapEntry = vmMapEntry.pptr(0x10);
            } else if (addr.addr() >= end) {
                // go right in tree
                vmMapEntry = vmMapEntry.pptr(0x18);
            } else {
                int prot = vmMapEntry.read1(0x64) & 0xFF;
                int maxprot = vmMapEntry.read1(0x65) & 0xFF;
                Status.println("    Start: 0x" + Long.toHexString(start));
                Status.println("    End: 0x" + Long.toHexString(end));
                Status.println("    Prot: " + Arrays.asList(ProtectionFlag.valueOf(prot)));
                Status.println("    Max Prot: " + Arrays.asList(ProtectionFlag.valueOf(maxprot)));
                Status.println("");
                return;
            }
        }
    }

    public int kMprotect(Process proc, Pointer addr, byte prot) {
        KernelPointer vmMapEntry = proc.getVmSpace().getPointer().pptr(OFFSET_VMROOT);
        while (!KernelPointer.NULL.equals(vmMapEntry)) {
            long start = vmMapEntry.read8(0x20);
            long end = vmMapEntry.read8(0x28);
            if (addr.addr() < start) {
                // go left in tree
                vmMapEntry = vmMapEntry.pptr(0x10);
            } else if (addr.addr() >= end) {
                // go right in tree
                vmMapEntry = vmMapEntry.pptr(0x18);
            } else {
                // protection
//                byte vmProt = vmMapEntry.read1(0x64);
//                vmProt |= prot;
                vmMapEntry.write1(0x64, prot);
                // max protection
//                byte maxProt = vmMapEntry.read1(0x65);
//                maxProt |= prot;
                vmMapEntry.write1(0x65, prot);
                return 0;
            }
        }
        return 0;
    }
}
