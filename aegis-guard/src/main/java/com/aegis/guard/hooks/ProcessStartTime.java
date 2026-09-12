package com.aegis.guard.hooks;

import java.util.OptionalLong;

import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Start time monotonico dei processi Windows (M2 Fase 3).
 *
 * <p>Via {@code GetProcessTimes}: con il PID forma la chiave anti-reuse
 * ({@link WindowsSensorKit#pidReuseKey}, v2 {@code procStartNs}). Su OS non
 * Windows, JNA assente o processo protetto ritorna vuoto — mai eccezioni,
 * il chiamante marca la copertura come degradata.
 */
public final class ProcessStartTime {

    private static final Logger log = LoggerFactory.getLogger(ProcessStartTime.class);

    private ProcessStartTime() {}

    /** 100-ns dal 1601-01-01 (FILETIME) o vuoto se non leggibile. */
    public static OptionalLong creationFileTime(long pid) {
        try {
            WindowsKernel32 kernel32 = WindowsKernel32.INSTANCE;
            Pointer h = kernel32.OpenProcess(
                    WindowsKernel32.PROCESS_QUERY_LIMITED_INFORMATION, false, (int) pid);
            if (h == null || h.equals(Pointer.NULL)) return OptionalLong.empty();
            try {
                WindowsKernel32.FILETIME.ByReference created =
                        new WindowsKernel32.FILETIME.ByReference();
                WindowsKernel32.FILETIME.ByReference exited =
                        new WindowsKernel32.FILETIME.ByReference();
                WindowsKernel32.FILETIME.ByReference kernel =
                        new WindowsKernel32.FILETIME.ByReference();
                WindowsKernel32.FILETIME.ByReference user =
                        new WindowsKernel32.FILETIME.ByReference();
                if (!kernel32.GetProcessTimes(h, created, exited, kernel, user)) {
                    return OptionalLong.empty();
                }
                return OptionalLong.of(created.toLong());
            } finally {
                kernel32.CloseHandle(h);
            }
        } catch (UnsatisfiedLinkError | NoClassDefFoundError e) {
            log.debug("GetProcessTimes non disponibile (non-Windows?): {}", e.getMessage());
            return OptionalLong.empty();
        } catch (Exception e) {
            return OptionalLong.empty();
        }
    }
}
