// https://github.com/john-tornblom/bdj-sdk/blob/master/samples/ps5-payload-loader/src/org/homebrew/libcInternal.java

package org.ps5jb.client.payloads.lib;

import org.ps5jb.sdk.core.Library;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.include.ErrNo;
import org.ps5jb.sdk.lib.LibKernel;

public class LibcInternal extends Library {
    private final LibKernel libKernel;

    public LibcInternal(LibKernel libKernel) {
        super(2);
        this.libKernel = libKernel;
    }

    /**
     * Gets the error message string corresponding to an error number
     * @param errno error number
     * @return error message corresponding to the error number
     */
    public String strerror(int errno) {
        long strAddr = call(addrOf("strerror"), errno);
        Pointer strPtr = new Pointer(strAddr);

        return strPtr.readString(null);
    }

    /**
     * Gets the error message of the last error
     * @return error message of the last error
     */
    public String strerror() {
        ErrNo errNo = new ErrNo(libKernel);

        return strerror(errNo.errno());
    }

    public int thrd_create(Pointer id, Pointer function, Pointer args) {
        Pointer thrd_create = addrOf("_Thrd_create");
        return (int) call(thrd_create, id.addr(), function.addr(), args.addr());
    }

    public int thrd_join(Pointer id, Pointer result) {
        // thrd_join(thrd_t thr, int *res);
        Pointer thrd_join = addrOf("_Thrd_join");
        return (int) call(thrd_join, id.addr(), result.addr());
    }
}
