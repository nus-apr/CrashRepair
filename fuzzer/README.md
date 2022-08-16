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
