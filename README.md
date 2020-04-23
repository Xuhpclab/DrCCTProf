# DrCCTProf

## Instructions for building DrCCTProf

### Linux

To build DrCCTProf on Linux, use the following commands as a guide. This builds 64-bit DrCCTProf in release mode:

```
# Install dependencies for Ubuntu 15+.  Adjust this command as appropriate for
# other distributions (in particular, use "cmake3" for Ubuntu Trusty).
$ sudo apt-get install cmake g++ g++-multilib doxygen transfig imagemagick ghostscript git zlib1g-dev
# Get sources.
$ git clone -recurse https://github.com/dolanzhao/DrCCTProf.git
# Then, simply type "sh build.sh" This will configure, make, and check DrCCTLib.
```
