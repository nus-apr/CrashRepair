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

TODO (Chris): add details
