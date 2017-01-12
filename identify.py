#!/usr/bin/env python

# Copyright (C) 2017 Thomas Rinsma / Riscure
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# System imports
import sys
import argparse
import gc
import re
import struct
import timeit
import time
from os.path import isfile, basename, splitext
from functools import partial
from operator import mul

# Packages
import Levenshtein
import editdistance

# Local files
from library_identification import ReferenceDB, LibraryFile
from prime_helpers import difference, primesbelow

# Globals
debug_enabled = True
primes_list = []


def debug(s, tmp=False):
    """
    Prints s if the global debug_enabled is True.
    Set tmp=True to print a cariage return before the line.
    """
    global debug_enabled
    if debug_enabled:
        prefix = "## "
        if tmp:
            sys.stderr.write('\r' + prefix + s)
        else:
            sys.stderr.write(prefix + s + '\n')
        sys.stdout.flush()


def compare_strings_concat_levenshtein(sample, ref):
    """
    Concatenates all strings from `sample` into one, and all strings
    from `ref` into another. They are then compared by their Levenshtein distance.
    This results in a fuzzy comparison: it detects changes within strings and
    within the list of strings.
    """
    if hasattr(ref, 'strs') and ref.strs is not None:
        i = 0
        ratios = 0
        for section in ref.strs:
            if section not in sample.strs:
                continue

            strs_a_concat = ''.join(sample.strs[section])
            strs_b_concat = ''.join(ref.strs[section])

            if len(strs_a_concat) == 0 or len(strs_b_concat) == 0:
                continue

            # Similarity meassurement from
            # Gheorghescu, M. (2005). An Automated Virus Classification System.
            # Virus Bulletin Conference, (October), 294-300.
            # (although they use it on a list of basic blocks instead of a
            # character string)
            
            ratio_sec = 1 - (Levenshtein.distance(strs_a_concat, strs_b_concat)
                            / float(max(len(strs_a_concat), len(strs_b_concat))))

            ratios += ratio_sec
            i += 1

        ratio = ratios / i if i > 0 else 0.0
    else:
        ratio = 0.0

    return (ratio * 100, ref.name, ref.version)


def compare_strings_set_union(sample, ref):
    """
    Treats the strings from `sample` and `ref` as two mathematical sets, thereby
    ignoring duplicates and order. These sets are then compared by taking the
    Jaccard index, also known as the 'overlap ratio'.
    """
    if hasattr(ref, 'strs') and ref.strs is not None:
        # Join all sections together into one set
        # there's probably a more efficient way to do this...
        strs_a_set = set.union(*[set(x) for x in sample.strs.values()])
        strs_b_set = set.union(*[set(x) for x in ref.strs.values()])

        # Set 'overlap' ratio:
        # |A /\ B| / |A \/ B|
        ratio = (len(set.intersection(strs_a_set, strs_b_set))
                / float(len(set.union(strs_a_set, strs_b_set))))
    else:
        ratio = 0.0

    return (ratio * 100, ref.name, ref.version)


def compare_cc_list_levenshtein(sample, ref):
    """
    Compares the cyclomatic complexity values of all functions in `sample`
    with those of all functions in `ref`, by taking the Levenshtein distance
    between these lists. This detects added/removed functions and functions
    that have changed in complexity between a sample and a reference.
    """
    if hasattr(ref, 'cclist') and ref.cclist is not None:
        ratio = 1 - (editdistance.eval(sample.cclist, ref.cclist)
                    / float(max(len(sample.cclist), len(ref.cclist))))
    else:
        ratio = 0.0

    return (ratio * 100, ref.name, ref.version)


def compare_cc_list_set_union(sample, ref, min_cc=1):
    """
    Treats the lists of cyclomatic complexity values of `sample` and `ref` as
    mathematical sets. These sets are then compared by taking the
    Jaccard index, their 'overlap ratio'.
    """
    if hasattr(ref, 'cclist') and ref.cclist is not None:
        cc_a_set = set(filter(lambda x: x > min_cc, sample.cclist))
        cc_b_set = set(filter(lambda x: x > min_cc, ref.cclist))

        # Set 'overlap' ratio:
        # |A /\ B| / |A \/ B|
        if len(set.union(cc_a_set, cc_b_set)) == 0:
            ratio = 0.0
        else:
            ratio = (len(set.intersection(cc_a_set, cc_b_set))
                    / float(len(set.union(cc_a_set, cc_b_set))))
    else:
        ratio = 0.0

    return (ratio * 100, ref.name, ref.version)


def compare_cc_spp(sample, ref, min_cc=1):
    """
    Compares the cyclomatic complexity values of the functions in `sample`
    and `ref` by comparing the factors in the small prime products of both.
    """
    global primes_list
    if hasattr(ref, 'cclist') and ref.cclist is not None:
        # NOTE: this is a demonstration. When implemented in a real, large system,
        # the product would be stored as the signature instead of the CC list.
        # In order to more accurately test the timing of such a scenario, the
        # numbers are multiplied and factored here.

        primes_a = map(lambda x: primes_list[x], sample.cclist)
        primes_b = map(lambda x: primes_list[x], ref.cclist)
        prod_a = reduce(mul, primes_a)
        prod_b = reduce(mul, primes_b)


        d = difference(prod_a, prod_b)
        if d == 0:
            ratio = 1.0
        else:
            ratio = 1 - d / float(max(len(sample.cclist), len(ref.cclist)))
    else:
        ratio = 0.0

    return (ratio * 100, ref.name, ref.version)


def compare_bb_hash_bloomfilter(sample, ref):
    """
    Compares `sample` and `ref` by comparing the bloomfilter signatures of
    basic-block hashes, as described by M. Gheorghescu in:
        "An Automated Virus Classification System,"
        Virus Bull. Conf., no. October, pp. 294-300, 2005.
    """
    def bitcount(x):
        # from https://blog.philippklaus.de/2014/10/counting-bits-set-to-1-in-bytes-with-python-popcount-or-hamming-weight
        # which in turn is based on http://go.klaus.pw/hamming-weights_python
        s = 0
        for n in struct.unpack('Q'*(len(x)//8), x):
            n -= (n >> 1) & 0x5555555555555555
            n = (n & 0x3333333333333333) + ((n >> 2) & 0x3333333333333333)
            n = (n + (n >> 4)) & 0x0f0f0f0f0f0f0f0f
            s += ((n * 0x0101010101010101) & 0xffffffffffffffff ) >> 56
        return s

    if hasattr(ref, 'bloomfilter') and ref.bloomfilter is not None:
        # Improved bloomfilter similarity ratio by Gheorghescu, Marius
        # d(x,y) = \sigma(x_i & y_i) / \sigma(x_i | y_i)

        ba_and = bytearray()
        ba_or = bytearray()
        for a,b in zip(sample.bloomfilter, ref.bloomfilter):
            ba_and.append(a & b)
            ba_or.append(a | b)

        ratio = bitcount(ba_and) / float(bitcount(ref.bloomfilter))
    else:
        ratio = 0.0

    return (ratio * 100, ref.name, ref.version)


def print_best_matches(matches, limit=10):
    """
    Given a list of result 3-tuples (as returned by compare_* functions)
    in `matches`, print the `limit` highest matching items.
    At the rightmost column of each line, a visualisation of the percentage
    is drawn. Additionally, the ratio of the similarity percentage of the
    current line versus the one above is printed to indicate the 'drop-off'
    ratio.
    """
    matches = [x for x in matches if x[0] > 0]
    if len(matches) != 0:
        # Sort by similarity (descending) and take the top `limit` matches
        matches_sorted = sorted(matches, key=lambda x: x[0], reverse=True)
        top_matches = matches_sorted[:limit] if limit > 0 else matches_sorted

        # Calculations for pretty printing
        max_name_len = len(max(top_matches, key=lambda (_,x,__): len(x))[1])
        max_ver_len = len(max(top_matches, key=lambda (_,__,x): len(x))[2])

        # Keep track of p_prev for the drop-off ratio
        (p_prev,_,_) = top_matches[0]
        for (p, libName, libVersion) in top_matches:
            print("%s %s  %6.2f%%  (x%6.2f)%s \t %s"
                  % (libName.ljust(max_name_len),
                    ("("+libVersion+")").ljust(max_ver_len + 2), p, p / p_prev,
                    "!" if (p / p_prev) <= 0.45 else " ",
                    make_pretty_bar(p, 20)))
            p_prev = p
    else:
        print("(none)")

    print("")


def perform_compares(sample, refs, cmp_function, one_version_per_lib=True):
    """
    Given `sample`, a list of `refs`, run `cmp_function` on all references and
    return a list of resulting 3-tuples. If `one_version_per_lib` is True,
    only the best matching version of each library is returned.
    """
    time_before = time.time()

    # For every library, compare all versions
    results = dict()
    for ref in refs:
        (p, name, version) = cmp_function(sample, ref)
        if name not in results:
            results[name] = dict()
        results[name][version] = p

    cmp_results = []
    if one_version_per_lib:
        # For every library, save best matching version
        for n in results:
            (v, p) = max(results[n].items(), key=lambda (v,p): p)
            cmp_results.append((p, n, v))
    else:
        # Save everything
        for n in results:
            for v in results[n]:
                cmp_results.append((results[n][v], n, v))

    time_after = time.time()
    debug("Running %s on %d refs took %fms"
          % (cmp_function.__name__, len(refs), (time_after - time_before) * 1000))

    return cmp_results


def pick_likely_matches(cmp_results, threshold_factor=0.65, min_percent=1.0, max_results=10):
    """
    Experimental function to filter a list of result 3-tuples based on the
    drop-off rates observed betweem the similarity percentages of the given matches.
    """

    # Throw away non-matches
    matches = [x for x in cmp_results if x[0] > 0]
    if len(matches) != 0:
        if len(matches) == 1:
            # Only one match, so it is the most likely
            return matches

        # Sort by match percentage, descending
        matches_sorted = sorted(matches, key=lambda x: x[0], reverse=True)

        # Iterate over all
        (p_prev,_,_) = matches_sorted[0]
        tentative_upper = 0
        for i in range(0, len(matches_sorted) - 1):
            (p, n, v) = matches_sorted[i]
            ratio = p / p_prev
            if ratio <= threshold_factor and p >= min_percent and i <= max_results:
                # Match percentage is <= threshold_factor times the one above,
                # so we would return everything above the current match.
                # However there could be another such drop, so keep iterating
                tentative_upper = i
            p_prev = p
        
        # Return the subset
        return matches_sorted[:tentative_upper]


def make_pretty_bar(percentage, width):
    """
    Returns a string containing a visual bar of `width` characters wide,
    filled in with `percentage` percentage of '#'.
    """
    num_on = int(round(width * percentage / 100.0))
    return ('|' + ('#' * num_on) + ('-' * (width - num_on)) + '|')


def load_sample_file(filename):
    """
    Given a sample `filename`, load it as a LibraryFile and generate the needed
    signature data. The resulting LibraryFile is returned.
    """

    # Load the file
    sample = LibraryFile(filename)

    # Get the list of CC values of the sample
    debug("Getting signature data from radare2 for %s" % sample.basename)
    sample.generate_r2_cfg()

    # Generate string list
    sample.grab_signature_strings()

    return sample


def benchmark(rdb, sample, refs):
    """
    Basic benchmarking function, call with a reference db `rdb`, a `sample`
    and a list of `refs`.
    """

    def bench1():
        return [compare_strings_concat_levenshtein(sample, ref)
                for ref in refs]

    def bench2():
        return [compare_strings_set_union(sample, ref)
                for ref in refs]
    def bench3():
        return [compare_cc_list_levenshtein(sample, ref)
                for ref in refs]

    def bench4():
        return [compare_cc_list_set_union(sample, ref)
                for ref in refs]

    def bench5():
        return [compare_cc_spp(sample, ref)
                for ref in refs]

    def bench6():
        return [compare_bb_hash_bloomfilter(sample, ref)
                for ref in refs]

    # Only run the slow ones a few times, and cc3 only once because of caching
    t1 = timeit.timeit(lambda: bench1(), setup="gc.enable()", number=5) / 5.0
    t2 = timeit.timeit(lambda: bench2(), setup="gc.enable()", number=100) / 100.0
    t3 = timeit.timeit(lambda: bench3(), setup="gc.enable()", number=100) / 100.0
    t4 = timeit.timeit(lambda: bench4(), setup="gc.enable()", number=100) / 100.0
    t5 = timeit.timeit(lambda: bench5(), setup="gc.enable()", number=1) / 1.0
    t6 = timeit.timeit(lambda: bench6(), setup="gc.enable()", number=100) / 100.0

    print(t1, t2, t3, t4, t5, t6)


def main():
    """
    Main entry point. Call with -h to see usage.
    """
    global primes_list, debug_enabled

    # Mapping of technique short-names to functions
    techniques = {
        "str1": compare_strings_concat_levenshtein,
        "str2": compare_strings_set_union,
        "cc1": compare_cc_list_levenshtein,
        "cc2": compare_cc_list_set_union,
        "cc3": compare_cc_spp,
        "bloom": compare_bb_hash_bloomfilter
    }

    # And long names
    techniques_long = {
        "str1": "Fuzzy string(-list) comparison using Levenshtein distance",
        "str2": "Exact set-based string-list comparison using Jaccard index",
        "cc1": "CC comparison using Levenshtein distance",
        "cc2": "CC set based comparison using Jaccard index",
        "cc3": "CC comparison using Small Prime Products",
        "bloom": "Basic-block hash comparison using Bloom filters"
    }

    def valid_technique(s):
        if s in techniques.keys():
            return s
        else:
            raise argparse.ArgumentTypeError("Invalid technique name '%s'." % s)

    # Parse commandline arguments
    parser = argparse.ArgumentParser(
        description="Compare a sample ELF file to a set of reference libraries.")
    parser.add_argument("sample", metavar="sample", type=str,
        help="Path to the sample file. Should be an ELF file, either a share object or an executable.")
    parser.add_argument("reference_db", type=str,
        help="Path to the DB generated by generate_db.py.")
    parser.add_argument("-q", action='store_true',
        help="Quiet: disable (most) debug output.")
    parser.add_argument("-lr", type=str, metavar="lib_regex",
        help="Only compare to libraries whose name (partly) matches this regex.")
    parser.add_argument("-vr", type=str, metavar="ver_regex",
        help="Only compare to libraries whose version string (partly) matches this regex.")
    parser.add_argument("-n", type=int, default=10, metavar="num_results",
        help="Maximum number of results to show per technique (default is 10).")
    parser.add_argument("-t", type=valid_technique, metavar="technique",
        help="Insteaf of all, perform only the provided technique (one of %s)." % str(techniques.keys()))
    args = parser.parse_args()

    if args.n < 1:
        print("ERROR: Invalid max number of results.")
        exit(1)

    if args.q:
        debug_enabled = False

    # Populate the prime list for quick factoring
    primes_list = primesbelow(16384*4) # Up to and including 65521

    # Set up reference DB
    rdb = ReferenceDB(args.reference_db)

    # Generate signature data for the sample file
    sample = load_sample_file(args.sample)

    # Try to find a version string, for manual analysis / verification
    version_strs = ", ".join(LibraryFile.get_version_strings(sample.strs))
    if version_strs:
        print("Found version string(s) in file: " + version_strs)

    # Grab the DB metadata contents
    debug("Comparing to the following reference libraries:")
    refsDict = dict()
    for refName in rdb.get_library_names():
        # Skip the library if a regex was given and it doesn't match
        if args.lr and not re.search(args.lr, refName):
            continue
        versions = rdb.get_library_versions(refName)

        # Filter versions if a version regex was given
        if args.vr:
            versions = filter(lambda v: re.search(args.vr, v) != None,
                              versions)
            if len(versions) == 0:
                continue
        debug("  %s: %d versions" % (refName, len(versions)))
        refsDict[refName] = versions
    if len(refsDict) == 0:
        print("No (matching) libraries/versions in the database, quitting.")
        exit(0)

    # Load all references
    all_refs = []
    for libName in refsDict:
        for libVersion in refsDict[libName]:
            ref = rdb.load_library(libName, libVersion)
            all_refs.append(ref)

    if args.t:
        # Perform only the given technique
        # Run all techniques and print the best matches of all
        print("\n%s. Results:" % techniques_long[args.t])
        res = perform_compares(sample, all_refs, techniques[args.t])
        print_best_matches(res, limit=args.n)
    else:
        # Run all techniques (in fixed order) and print the best matches of each
        for tech in ["str1", "str2", "cc1", "cc2", "cc3", "bloom"]:
            print("\n%s. Results:" % techniques_long[tech])
            res = perform_compares(sample, all_refs, techniques[tech])
            print_best_matches(res, limit=args.n)


if __name__ == "__main__":
    main()
