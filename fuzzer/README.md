# Documentation for Concentrated Fuzzing

Our fuzzing component is based on the concentrated fuzzer by [VulnLoc](https://github.com/VulnLoc/VulnLoc).

## Prepare the fuzzer

The fuzzer is integrated in the HiFix build pipeline. You can trigger the build within the `docker` folder with

```
make
```

to trigger the complete build (incl. the fuzzer), or 

```
make fuzzer
```

to only build the fuzzer docker image. To run the fuzzer inside the [SecBugs](https://github.com/squaresLab/security-repair-benchmarks) environment, you also need to run `install`, which however requires the other images as well. Therefore, if you only want to test the fuzzer on our benchmark, please modify the `install` file accordingly.

## Configuraton File: config.ini
*adapted from: https://github.com/VulnLoc/VulnLoc*

#### Required options:
* **cve_tag:** The unique ID of each CVE (e.g., cve_2016_5314). A configuration file can include the information for multiple CVE. For extracting the right configuration, users are required to assign a unique ID for each CVE.
* **trace_cmd:** The command used for executing the vulnerable program with the given PoC. Each argument is separate by ';'. The location of the target argument for fuzzing is replaced with '***'.
* **crash_cmd:** The command used for checking whether the vulnerable program gets exploited or not. crash_cmd follows the same format as trace_cmd.
* **bin_path:** The path to the vulnerable binary.
* **poc:** The path to the PoC
* **poc_fmt:** The type of PoC.
* **mutate_range:** The valid range for mutation.
* **folder:** The output folder for saving the test-suite.
* **crash_tag:** The information which can be utilized to detect whether the program gets exploited or not. The vulnerablity checker is defined in the function check_exploit under ./code/fuzz.py.

#### Additional, originally undocumented but relevant, options:
* **combination_num:** Determines the maximum number of combinations during the mutation process. Default=2.

#### New/added options:
* **store_all_inputs:** Set to `True` to generate all inputs.


## Instructions for example `cve_2016_5314`

Assuming you have successfully build the fuzzer, you can go ahead and use the fuzzer in the [SecBugs](https://github.com/squaresLab/security-repair-benchmarks) environment: [https://github.com/squaresLab/security-repair-benchmarks
](https://github.com/squaresLab/security-repair-benchmarks)
### 1. Build the secbugs Docker image

```
git submodule update --init --recursive
make
```

### 2. Start secbugs container

```
./scripts/run.sh
```


### 5. Prepare binary

```
cd /benchmarks/libtiff/cve_2016_5314
./build-for-fuzzer
```


### 6. Modify configuration (if needed)

```
vi /benchmarks/libtiff/cve_2016_5314/config.ini
```

For example, to store *all* mutated inputs you can add the property:

```
store_all_inputs=True
```

To avoid memory overloads you can limit the fuzzers' mutations with:

```
combination_num=1
```


### 7. Run fuzzer

```
/opt/fuzzer/code/fuzz --config_file config.ini --tag cve_2016_5314
```

... wait for specified time bound in config.ini (current default setup is 5 min for testing purpose)


### 8. Check generated inputs

The `config.ini` file defines the output folder:
```
folder=/benchmarks/libtiff/cve_2016_5314
```

*Inside* this folder the fuzzer will generate the following folders/files:

```
fuzzer
|_ concentrated_inputs/
|_ all_inputs/
|_ fuzz.log
```

* `concentrated_inputs` includes the files that new traces with regard to the exploit
* `all_inputs` include all mutated inputs (depending on the configuration)
* `fuzz.log` contains the output log
