package benchmark;

import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.VerboseMode;

public class Main {
    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                //.exclude(".*cryptFile.*")
                .resultFormat(ResultFormatType.JSON)
                .result("crypto-benchmark-result_" + System.currentTimeMillis() + ".json")
                .shouldFailOnError(true)
                .verbosity(VerboseMode.EXTRA)
                .build();

        new Runner(opt).run();
    }
}
