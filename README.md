# DrCCTProf - DrPy Client

DrPy client aims to detect and optimize cross layer inefficiencies across Python program and native layers.

DrCCTProf is a fine-grained call path profiling framework for binaries running on ARM and X86 architectures. DrCCTProf (together with its predecessor CCTLib) won a numbe of paper awards, including ASPLOS'17 Highlight, ICSE'19 Distinguished Paper Award, SC'20 Best Paper Finalist. 

-   Please see our [blog](https://xl10.github.io/blog/drcctprof.html) for the high-level introduction.
-   Please watch our [introductory talk](https://www.youtube.com/watch?v=oUB9yh_78hE) to learn more.
-   Please refer [documentation](https://drcctprof.readthedocs.io/en/latest/) for detailed tutorial and API references. 
-   Please refer to [the DrCCTProf tutorial](https://www.xperflab.org/drcctprof/tutorial) co-located with CGO'22.

![build master](https://github.com/Xuhpclab/DrCCTProf/workflows/build%20master/badge.svg)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/d9708750f8b24b60bc0102dd5b89e4dd)](https://www.codacy.com/gh/Xuhpclab/DrCCTProf/dashboard?utm_source=github.com&utm_medium=referral&utm_content=Xuhpclab/DrCCTProf&utm_campaign=Badge_Grade)
![license](https://img.shields.io/github/license/Xuhpclab/DrCCTProf)

## Contents

-   [Installation](#installation)
-   [Usage](#usage)
-   [Client tools](#client-tools)
-   [Supported Platforms](#support-platforms)
-   [Obtaining Help](#obtaining-help)
-   [License](#license)

## Installation

### Linux

#### 1 Install dependencies

In order to build you'll need the following packages:

-   gcc (>= 4.8)
-   binutils (>= 2.26)
-   [cmake](https://cmake.org/download/) (>= 3.7)
-   perl

To avoid version conflicts with any packages, we recommend to use [Spack](https://spack.io/) to manage the above packages and create a virtual environment to build and run DrCCTProf. 

#### 2 Build

Use the following commands to get source code and build DrCCTProf:

```console
$ git clone --recurse https://github.com/Xuhpclab/DrCCTProf.git
```

```console
$ ./build.sh
```

## Usage

### Linux

To run DrCCTProf, one needs to use the following command:

#### 1 Set the global environment variable

```console
$ export drrun=/path/to/DrCCTProf/build/bin64/drrun
```

#### 2 Run client tool

-   **x86_64**

```console
$ $drrun -t <client tool> -- <application> [apllication args]
```

e.g. The command below will start the client **drcctlib_instr_statistics_clean_call** to analyze **echo _"Hello World!"_**.

```console
$ $drrun -t drcctlib_instr_statistics_clean_call -- echo "Hello World!"
```

-   **aarch64**

```console
$ $drrun -unsafe_build_ldstex -t <client tool> -- <application> [apllication args]
```

## Client tools

### Internal client tools list

| Name                                 | Features                                                                    | Status  |
| ------------------------------------ | --------------------------------------------------------------------------- | ------- |
| drcctlib_cct_only_clean_call         | A tool that collects call path on each instruction.                         | release |
| drcctlib_instr_statistics_clean_call | A instruction counting tool that counts each instruction.                   | release |
| drcctlib_reuse_distance_client_cache | A reuse distance measurement tool.                                          | release |
| drcctlib_cct_only                    | (Code cache mode)A tool that collects call path on each instruction.        | beta    |
| drcctlib_instr_statistics            | (Code cache mode) A instruction counting tool that counts each instruction. | beta    |
| drcctlib_reuse_distance              | (Code cache mode) A reuse distance measurement tool.                        | beta    |


## Support Platforms

The following platforms pass our tests.

### Linux

| CPU                               | Systems       | Architecture |
| --------------------------------- | ------------- | ------------ |
| Intel(R) Xeon(R) CPU E5-2699 v3   | Ubuntu 18.04  | x86_64       |
| Intel(R) Xeon(R) CPU E5-2650 v4   | Ubuntu 14.04  | x86_64       |
| Intel(R) Xeon(R) CPU E7-4830 v4   | Red Hat 4.8.3 | x86_64       |
| Arm Cortex A53(Raspberry pi 3 b+) | Ubuntu 18.04  | aarch64      |
| Arm Cortex-A57(Jetson Nano)       | Ubuntu 18.04  | aarch64      |
| ThunderX2 99xx                    | Ubuntu 20.04  | aarch64      |
| AWS Graviton1                     | Ubuntu 18.04  | aarch64      |
| AWS Graviton2                     | Ubuntu 18.04  | aarch64      |
| Fujitsu A64FX                     | CentOS 8.1    | aarch64      |

## Obtaining Help

### Report an error case of building

Please use the [build error report](https://github.com/Xuhpclab/DrCCTProf/issues/new?labels=build-error&template=build_error.md&title=Build+error).

DrCCTProf is built atop [DynamoRIO](https://github.com/DynamoRIO/dynamorio). If you get errors in building, you can also search the [DynamoRIO's issues](https://github.com/DynamoRIO/dynamorio/issues) to get help.

### Report a bug

Please use the [bug report](https://github.com/Xuhpclab/DrCCTProf/issues/new?labels=bug-report&template=bug_report.md&title=Bug+report).

## License

DrCCTProf is released under the [MIT License](http://www.opensource.org/licenses/MIT).

## Related Publication
1. Milind Chabbi, Xu Liu, and John Mellor-Crummey. 2014. Call Paths for Pin Tools. In Proceedings of Annual IEEE/ACM International Symposium on Code Generation and Optimization (CGO '14). ACM, New York, NY, USA, , Pages 76 , 11 pages. DOI=http://dx.doi.org/10.1145/2544137.2544164
2. Milind Chabbi, Wim Lavrijsen, Wibe de Jong, Koushik Sen, John Mellor-Crummey, and Costin Iancu. 2015. Barrier elision for production parallel programs. In Proceedings of the 20th ACM SIGPLAN Symposium on Principles and Practice of Parallel Programming (PPoPP 2015). ACM, New York, NY, USA, 109-119. DOI=http://dx.doi.org/10.1145/2688500.2688502
3. Milind Chabbi and John Mellor-Crummey. 2012. DeadSpy: a tool to pinpoint program inefficiencies. In Proceedings of the Tenth International Symposium on Code Generation and Optimization (CGO '12). ACM, New York, NY, USA, 124-134. DOI=http://dx.doi.org/10.1145/2259016.2259033
4. Shasha Wen, Xu Liu, Milind Chabbi, "Runtime Value Numbering: A Profiling Technique to Pinpoint Redundant Computations"  The 24th International Conference on Parallel Architectures and Compilation Techniques (PACT'15), Oct 18-21, 2015, San Francisco, California, USA
5. Shasha Wen, Milind Chabbi, and Xu Liu. 2017. REDSPY: Exploring Value Locality in Software. In Proceedings of the Twenty-Second International Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS '17). ACM, New York, NY, USA, 47-61. DOI: https://doi.org/10.1145/3037697.3037729
6. Pengfei Su, Shasha Wen, Hailong Yang, Milind Chabbi, and Xu Liu. 2019. Redundant Loads: A Software Inefficiency Indicator. In Proceedings of the 41st International Conference on Software Engineering (ICSE '19). IEEE Press, Piscataway, NJ, USA, 982-993. DOI: https://doi.org/10.1109/ICSE.2019.00103
7. Jialiang Tan, Shuyin Jiao, Milind Chabbi, Xu Liu. What Every Scientific Programmer Should Know About Compiler Optimizations? The 34th ACM International Conference on Supercomputing (ICS'20), Jun 29 - Jul 2, 2020, Barcelona, Spain. 
8. Xin You, Hailong Yang, Zhongzhi Luan, Depei Qian, Xu Liu. Zerospy: Exploring the Software Inefficiencies with Redundant Zeros, The International Conference for High Performance Computing, Networking, Storage and Analysis (SC'20), Nov 15-20, 2020, Atlanta, GA, USA.
9. Qidong Zhao, Xu Liu, Milind Chabbi. DRCCTPROF: A Fine-grained Call Path Profiler for ARM-based Clusters, The International Conference for High Performance Computing, Networking, Storage and Analysis (SC'20), Nov 15-20, 2020, Atlanta, GA, USA. 
