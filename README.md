# Library Identification Tool

This is a research tool implementing several signature creation and comparison techniques for the purpose of identifying the version of shared library files and libraries contained in statically linked binaries.

Information about the techniques and an analysis of their effectiveness for this purpose can be found in the [associated paper on arXiv](https://arxiv.org/abs/1703.00298).

## Disclaimer
This code was written during a research internship project by me (Thomas Rinsma). It is not a Riscure product and Riscure does not support or maintain this code. Please feel free to make a pull request if you have something to contribute :)


## Installation

1. Install radare2 from GitHub: https://github.com/radare/radare2 (last tested commit: `db0f4da4ff07a57709ea3648d7880ade9e30e56c`, but `HEAD` should work)

2. Make sure you have Python 2.7+ (not tested with 3), `pip` and `virtualenv` installed.

3. Clone the project into `library-identification` and `cd` into it.

4. Create and activate a virtualenv:
   `virtualenv -p /path/to/python2.7 venv`
   `source venv/bin/activate`

5. Download and install the dependencies:
	`pip install -r requirements.txt`

## Usage
The tool provides two scripts: `identify.py` and `generate_db.py`. Both accept the `-h` flag to show info about additional command line options (like regex-based filtering and parallel signature generation)


To start, generate a signature database:

1. Gather reference libraries and make sure they are named according to the pattern `libname__libversion.so`
2. Create and populate a signature database:
    `mkdir signature_db`
    `./generate_db.py signature_db *.so`

Now we can match unknown samples against these reference versions. Some example scenarios:

- You have a shared library file `libfoobar.so` but you're not sure of its exact version. You run all techniques against all versions of `libfoobar` in your database to get a top 5 of most likely versions from each technique:
    `./identify.py -lr libfoobar -n 5 libfoobar.so signature_db`
- You have a statically linked binary `some_bin` and you want to detect any libraries that it was linked with, using only the exact string-list similarity technique (`str2`):
    `./identify.py -t str2 some_bin signature_db`

