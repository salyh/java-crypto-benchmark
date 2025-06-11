package benchmark.ciphers.libsodium;

import java.lang.foreign.Arena;
import java.lang.foreign.SymbolLookup;
import java.nio.file.Path;
import java.util.Set;

public class LibsodiumLoader {

    private final static Set<String> libsodiumPaths = Set.of(
            "/opt/homebrew/lib/libsodium.dylib",
            "/usr/local/lib/libsodium.dylib",
            "/usr/lib/x86_64-linux-gnu/libsodium.so"
    );

    static SymbolLookup loadLibcrypto() {
        for (String path : libsodiumPaths) {
            try {
                return SymbolLookup.libraryLookup(Path.of(path), Arena.global());
            } catch (Throwable e) {
                //suppress the error, we will try the next path
            }
        }
        throw new LibsodiumException("Could not find libsodium library");
    }

}
