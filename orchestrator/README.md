## Orchestrator Module

The orchestrator provides a simple command-line front-end for CrashRepair which integrates its analysis, repair, and fuzzing modules.

## Usage

The orchestrator is bundled as a standalone executable, `crashrepair`, in the all-in-one Docker image for CrashRepair.
To run the orchestrator on a given bug scenario, you should execute the following:

```
crashrepair repair bug.json
```

where `bug.json` points to the bug.json file for the bug scenario.
Details on the format of `bug.json` are provided below.

Note that the following options can be passed to the `repair` command above:

* `--no-fuzzing`: disables the use of the concentrated fuzzer to create additional test cases for patch validation
* `--stop-early`: instructs CrashRepair to stop running as soon as the first plausible patch has been discovered.
  A plausible patch is one that passes both the proof-of-crash and all of the additional fuzzer-generated tests.
  If this option is not enabled, CrashRepair will produce as many repairs until either it has reached a resource limit (e.g., wall-clock time, number of patches) or all candidate repairs have been exhausted.

For a more complete and up-to-date list of command-line options, use `--help`:

```
crashrepair repair --help
```


## `bug.json` File Format

Below is an example of a `bug.json` file, taken from the `buffer-overflow/dynamic-array` test program:

```json
{
  "project": {
    "name": "buffer-overflow"
  },
  "name": "dynamic-array",
  "binary": "src/test",
  "crash": {
    "command": "$POC",
    "input": "./exploit",
    "extra-klee-flags": "",
    "expected-exit-code": 0
  },
  "source-directory": "src",
  "build": {
    "directory": "src",
    "binary": "test",
    "commands": {
      "prebuild": "exit 0",
      "clean": "make clean",
      "build": "make"
    }
  }
}
```

* The `crash` section is used to provide the CrashRepair analyzer with the necessary information to diagnose the crash and produce an annotated fix localization. **(FIXME: resolve ambiguity between file-based and argument-based inputs.)**
  * The optional `extra-klee-flags` property is used to inject additional KLEE flags, given as a string, at link time when the analyzer rebuilds the program.
    In all cases, `--link-llvm-lib=/CrashRepair/lib/libcrepair_proxy.bca` will always be injected as a KLEE flag.
  * The `expected-exit-code` property is used to specify what exit code should be produced by the program if the crash is resolved.
    If this property is left unspecified, it assumes its default value of `0`.
