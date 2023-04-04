# CrashRepair

A program repair tool for security vulnerabilities in C programs.

## Getting Started

**Installation:** We provide a Docker image that contains both CrashRepair and the evaluation dataset.
To install that Docker image, you should execute the following:

    ./scripts/install

Note that the installation process can take more than an hour depending on available hardware.

**Running:** To run CrashRepair on one of the scenarios from the dataset, you can use the `scripts/run` script after following the installation instructions above.
You should provide the name of the program and the scenario as separate positional arguments to the script, as shown below:

    ./scripts/run zziplib CVE-2017-5974

Upon completion, a summary of the results (`report.json`) will be written to the appropriate `results` subdirectory (e.g., `results/zziplib/CVE-2017-5974/report.json`).
If any acceptable patches are discovered they will be added to a `patches` directory within that scenario's results subdirectory (e.g., `results/zziplib/CVE-2017-5974/patches`).

The behavior of `scripts/run` can be customized via the following environment variables:

* `REPAIR_TIME_LIMIT` specifies the maximum length of time (minutes) for which the repair can run. **(Default: 45 minutes.)**
* `TEST_TIME_LIMIT` specifies the maximum length of time (seconds) that the failing test case should be allowed to run. **(Default: 30 seconds.)**
* `MEMORY_LIMIT` used to set Docker's `--memory` option (see https://docs.docker.com/config/containers/resource_constraints). **(Default: 16g.)**
* `CPU_LIMIT` used to set Docker's `--cpus` option (see https://docs.docker.com/config/containers/resource_constraints). **(Default: 8.)**

For example, to run CrashRepair with 8 CPU cores and 16 GiB RAM with a 60-minute time limit:

    REPAIR_TIME_LIMIT=60 CPU_LIMIT=8 MEMORY_LIMIT=16 ./scripts/run zziplib CVE-2017-5974

To run CrashRepair on all of the scenarios in the dataset with a single command, you can use the `scripts/run-all` script.
This script takes a single command-line option (in addition to the same environment variables as `scripts/run`), specifying the number of workers that should be used to run scenarios in parallel.
For example, to run CrashRepair with two parallel workers:

    ./scripts/run-all -j 2

(Note that the space between `-j` and `2` is necessary.)

## Development

To build and run a Docker image that contains only the tool and regression tests:

    make -C docker crepair
    docker run --rm -it crepair:tool

To hop inside the all-in-one Docker image for the purpose of debugging:

    docker run --rm -it crepair:aio
