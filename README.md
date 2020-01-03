# drcctlib

## Instructions for building DrCCTLib

### Linux

To build DrCCTLib on Linux, use the following commands as a guide. This builds 64-bit DrCCTLib in release mode:

```
# Install dependencies for Ubuntu 15+.  Adjust this command as appropriate for
# other distributions (in particular, use "cmake3" for Ubuntu Trusty).
$ sudo apt-get install cmake g++ g++-multilib doxygen transfig imagemagick ghostscript git zlib1g-dev
# Get sources.
$ git clone https://github.com/dolanzhao/drcctlib.git
# Then, simply type "sh build.sh" This will configure, make, and check DrCCTLib.
```