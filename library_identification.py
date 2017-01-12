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
import string
import re
import hashlib
import gzip
import json
import cPickle as pickle
import itertools
import operator
from os.path import basename, splitext, isdir, exists, join, getsize
from os import listdir, makedirs
from binascii import crc32

# Packages
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

# Local files
from r2_cfg_wrapper import R2CFGWrapper


class ReferenceDB:
    """
    Handles the storage of library version signature data.

    Uses the filesystem to store pickled LibraryFile instances,
    ordered by the libraryname. Looks like this:

    path/
      libabc/
        metadata.json
        1.2.pickle
        1.2.{dynstr,rodata,...}.strings
        1.3.pickle
        1.3.{dynstr,rodata,...}.strings
      libxyz/
        metadata.json
        3.4.5-bla.pickle
        3.4.5-bla.{dynstr,rodata,...}.strings
        1.2.3.4.pickle
        1.2.3.4.{dynstr,rodata,...}.strings

    The metadata files look like this:
    {
      "1.2.3":
      {
        "file_hash": "3b854f5e13be0328b7c7701ff679223c72d64550"
        "strings_sections" :
          {
             ".dynstr" : "1.2.3.dynstr.strings",
             ".rodata" : "1.2.3.rodata.strings"
          }
      },
      ...
    }
    """

    METADATA_FILENAME = "metadata.json"
    STRINGS_EXTENSION = ".strings"
    PICKLE_EXTENSION = ".pickle"

    def __init__(self, path):
        self.path = path

        # Make sure the folder exists
        if not exists(path) or not isdir(path):
            raise IOError("Given path does not exist")


    def get_library_names(self):
        """
        Returns the list of library names of which
        we have versions stored
        """
        return [f for f in listdir(self.path) if isdir(join(self.path, f))]


    def get_library_versions(self, lib_name):
        """
        For a given library name, returns the list
        of versions that we have stored
        """
        if not isdir(join(self.path, lib_name)):
            return []
        return self.read_metadata(lib_name).keys()

    def read_metadata(self, lib_name):
        """
        Read the metadata file for a given library name
        """
        with open(join(self.path, lib_name, self.METADATA_FILENAME), "r") as file:
            return json.load(file)


    def update_metadata(self, lib):
        """
        Update the metadata file associated with the given libary,
        creates the metadata file if needed.
        """
        fileHash = ReferenceDB.get_file_hash(lib.filename)

        # If the file already exists, append to it.
        if not exists(join(self.path, lib.name, self.METADATA_FILENAME)):
            md = dict()
        else:
            with open(join(self.path, lib.name, self.METADATA_FILENAME), "r") as file:
                md = json.load(file)

        if lib.version not in md:
            md[lib.version] = dict()

        md[lib.version]["file_hash"] = fileHash
        md[lib.version]["strings_sections"] = {s : "%s%s%s"
            % (lib.version, s, self.STRINGS_EXTENSION) for s in lib.strs}

        with open(join(self.path, lib.name, self.METADATA_FILENAME), "w") as file:
            json.dump(md, file, sort_keys=True, indent=4)


    def exists_in_db(self, filename):
        """
        Returns True if there exists a file in the DB with the same
        library name and hash as the given file
        """
        [name, _] = splitext(basename(filename))[0].split('__')

        if not exists(join(self.path, name, self.METADATA_FILENAME)):
            return False
            
        newHash = ReferenceDB.get_file_hash(filename)
        metadata = self.read_metadata(name)

        # Check all versions of the library, as identified by the filename
        for version in metadata:
            if metadata[version]['file_hash'] == newHash:
                return True

        return False


    def write_library(self, lib, gzipped=False):
        """
        Writes the given LibraryFile to disk, writes string list to
        the strings file, and updates metadata
        """

        # Create folder if needed
        if not exists(join(self.path, lib.name)):
            makedirs(join(self.path, lib.name))

        # Write the strings list for every section
        for section in lib.strs:
            # HACK: This works out because section names start with a period...
            sec_strs_path = join(self.path, lib.name, lib.version
                                 + section + self.STRINGS_EXTENSION)
            with ReferenceDB.open_file(sec_strs_path, "w", gzipped=False) as file:
                strs_concat = '\n'.join(x.encode('string_escape') for x in lib.strs[section])
                file.write(strs_concat + '\n')

        # Update the metadata file
        self.update_metadata(lib)

        # Write the LibraryFile pickle itself
        full_path = join(self.path, lib.name, lib.version + self.PICKLE_EXTENSION)
        with ReferenceDB.open_file(full_path, "wb", gzipped=gzipped) as file:
            lib.strs = None
            pickle.dump(lib, file, -1)


    def get_library_strings(self, lib_name, lib_version):
        def decoded_lines_generator(file):
            for line in file:
                # Strip the newline
                if line[-1] == '\n':
                    l = line[:-1].decode('string_escape')
                else:
                    l = line.decode('string_escape')

                if l != '':
                    yield l

        strings_sects = self.read_metadata(lib_name)[lib_version]["strings_sections"]
        strs = dict()
        for s in strings_sects:
            sec_strs_path = join(self.path, lib_name, strings_sects[s])
            with ReferenceDB.open_file(sec_strs_path, "r") as file:
                strs[s] = list(decoded_lines_generator(file))

        return strs


    def load_library(self, lib_name, lib_version, load_strings=True):
        """
        Returns the LibraryFile of requested library name
        and version, or None. Loads the contents of the
        strings file into .strs if load_strings is True.
        """

        # Load the LibraryFile
        full_path = join(self.path, lib_name, lib_version + self.PICKLE_EXTENSION)
        with ReferenceDB.open_file(full_path, "rb") as file:
            lib = pickle.load(file)
            if load_strings:
                lib.strs = self.get_library_strings(lib_name, lib_version)
            return lib


    @staticmethod
    def open_file(path, attrs, gzipped=True):
        """
        Abstracts away the gzipping.
        """
        if gzipped:
            if "r" in attrs:
                # Try regular first
                if exists(path):
                    return open(path, attrs)
                else:
                    return gzip.open(path + ".gz", attrs)
            else:
                return gzip.open(path + ".gz", attrs)

        return open(path, attrs)


    @staticmethod
    def get_file_hash(filename):
        """
        Returns the SHA1 hash of the given file.
        """

        hasher = hashlib.sha1()
        BLOCKSIZE = 65536
        with open(filename, 'rb') as f:
            buf = f.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(BLOCKSIZE)

        return hasher.hexdigest()

class LibraryFile:
    """
    Represents a library file (i.e. a shared object file), with
    methods to generate signature data.
    """

    ignore_strings = [
        ".ARM.attributes",
        ".bss",
        ".comment",
        ".data",
        ".data.rel.ro",
        ".divsi3_skip_div0_test",
        ".dynamic",
        ".dynstr",
        ".dynsym",
        ".eh_frame",
        ".fini",
        ".fini_array",
        ".gnu.attributes",
        ".gnu.hash",
        ".gnu.version",
        ".gnu.version_r",
        ".hash",
        ".init",
        ".init_array",
        ".mdebug.abi32",
        ".MIPS.abiflags",
        ".note.GNU-stack",
        ".note.gnu.build-id",
        ".reginfo",
        ".rel.data.rel.local",
        ".rel.dyn",
        ".rel.pdr",
        ".rel.plt",
        ".rel.text",
        ".rela.data.rel.local",
        ".rela.eh_frame",
        ".rela.text",
        ".rodata",
        ".sdata",
        ".shstrtab",
        ".strtab",
        ".symtab",
        ".text",
        ".udivsi3_skip_div0_test",
        "__adddf3",
        "__aeabi_cdcmpeq",
        "__aeabi_cdcmple",
        "__aeabi_cdrcmple",
        "__aeabi_d2iz",
        "__aeabi_dadd",
        "__aeabi_dcmpeq",
        "__aeabi_dcmpge",
        "__aeabi_dcmpgt",
        "__aeabi_dcmple",
        "__aeabi_dcmplt",
        "__aeabi_ddiv",
        "__aeabi_dmul",
        "__aeabi_drsub",
        "__aeabi_dsub",
        "__aeabi_f2d",
        "__aeabi_i2d",
        "__aeabi_idiv",
        "__aeabi_idiv0",
        "__aeabi_idivmod",
        "__aeabi_l2d",
        "__aeabi_ldiv0",
        "__aeabi_ui2d",
        "__aeabi_uidiv",
        "__aeabi_uidivmod",
        "__aeabi_ul2d",
        "__bss_end__",
        "__bss_start",
        "__bss_start__",
        "__clzsi2",
        "__cmpdf2",
        "__ctzsi2",
        "__cxa_finalize",
        "__cxa_finalize@@GLIBC_2.4",
        "__divdf3",
        "__divsi3",
        "__do_global_dtors_aux",
        "__do_global_dtors_aux_fini_array_entry",
        "__dso_handle",
        "__end__",
        "__eqdf2",
        "__extendsfdf2",
        "__fixdfsi",
        "__floatdidf",
        "__floatsidf",
        "__floatundidf",
        "__floatunsidf",
        "__frame_dummy_init_array_entry",
        "__FRAME_END__",
        "__gedf2",
        "__gmon_start__",
        "__gtdf2",
        "__JCR_END__",
        "__JCR_LIST__",
        "__ledf2",
        "__ltdf2",
        "__muldf3",
        "__nedf2",
        "__subdf3",
        "__TMC_END__",
        "__udivsi3",
        "_bss_end__",
        "_DYNAMIC",
        "_edata",
        "_fbss",
        "_fdata",
        "_fini",
        "_ftext",
        "_GLOBAL_OFFSET_TABLE_",
        "_gp_disp",
        "_init",
        "_ITM_deregisterTMCloneTable",
        "_ITM_registerTMCloneTable",
        "_Jv_RegisterClasses",
        "deregister_tm_clones",
        "GLIBC_2.4",
        "register_tm_clones",
    ]

    def __init__(self, filename):
        self.filename = filename
        self.basename = basename(filename)

        # ELF data
        self.arch = ""
        self.elf_sections = dict() # {'name' : (offset, size), ...}

        # Library name and version strings
        self.name = ""
        self.version = ""

        # Signature data
        self.size = 0
        self.tinycfg = None
        self.cclist = None
        self.bloomfilter = None
        self.strs = None

        self.check_file()

    # Make sure the file is valid and extract name and version from filename
    def check_file(self):
        try:
            # Parse the ELF header
            elffile = ELFFile(open(self.filename, 'rb'))

            # Grab architecture (e.g. 'MIPS' from 'EM_MIPS')
            self.arch = elffile.header.e_machine.split('_')[1]

            # Grab ELF section info
            for section in elffile.iter_sections():
                self.elf_sections[section.name] = (section.header['sh_offset'],
                                                   section.header['sh_size'])

        except IOError:
            print("ERROR: Could not load the file '" + self.filename + "'.")
            exit(1)
        except ELFError:
            print("ERROR: '" + self.filename + "' is not a valid ELF object")
            exit(1)

        # Parse name and version from filename
        try:
            [self.name, self.version] = splitext(self.basename)[0].split('__')
        except:
            self.name = self.basename
            self.version = "unknown"

        # Get file size
        self.size = getsize(self.filename)


    # Grabs signature data from radare2
    def generate_r2_cfg(self):
        # Load the file into r2
        r2w = R2CFGWrapper(self.filename)

        # Retrieve the CC list from r2
        self.cclist = r2w.get_cyclomatic_complexity_list()

        # Retrieve the full CFG
        #self.r2cfg = r2w.getCFG()

        # Set bits in the bloom filter
        BLOOM_FILTER_SIZE = 1024 * 4 # 4KByte
        self.bloomfilter = bytearray(BLOOM_FILTER_SIZE)

        # For every function, get the hash
        for h in r2w.get_bb_hashes():
            # Calculate the position of the bit to set
            bitpos = h % (BLOOM_FILTER_SIZE * 8)

            # Set the right bit in the right byte of the bytearray
            self.bloomfilter[bitpos / 8] |= (1 << (bitpos % 8))

        r2w.r2.quit()


    # Grab and save the strings we can use for recognition
    def grab_signature_strings(self):
        # Sections of which we want strings
        sections = ['.dynstr', '.rodata', '.data', '.strtab']

        self.strs = dict()
        for section in sections:
            self.strs[section] = list(self.get_strings(section=section))


    # Retrieves readable strings from a (section of an ELF) file
    def read_strings(self, section=None):
        i = 0
        inString = False
        curStr = bytearray('')
        try:
            f = open(self.filename, 'rb')
            if section:
                if section not in self.elf_sections:
                    return
                (offset, size) = self.elf_sections[section]
                f.seek(offset)
            byte = f.read(1)
            while byte != "" and f.tell() < offset + size:
                # Between space and tilde (i.e printable and non-special)
                if ord(byte) >= 0x20 and ord(byte) < 0x7F:
                    if not inString:
                        # Skip whitespace at start of strings?
                        #while byte in string.whitespace:
                        #   byte = f.read(1)

                        # We're in a new string
                        inString = True

                        # Yield the latest string
                        if str(curStr) not in LibraryFile.ignore_strings:
                            yield str(curStr)

                        curStr = bytearray('')
                    
                    curStr.append(byte)
                else:
                    inString = False

                byte = f.read(1)

            # Return the final string, if needed
            if inString and str(curStr) not in LibraryFile.ignore_strings:
                yield str(curStr)

            f.close()
        except IOError:
            pass

    # Returns strings of appropriate minimum length, sorted and unique
    def get_strings(self, section=None, minLength=5):
        # fast generator-friendly version of uniq+sort
        # from http://stackoverflow.com/questions/2931672/
        def sort_uniq(sequence):
            return itertools.imap(
                operator.itemgetter(0),
                itertools.groupby(sorted(sequence)))

        return sort_uniq(itertools.ifilter(lambda s: len(s) >= minLength,
                           self.read_strings(section=section)))


    # Returns strings that look like a version number
    @staticmethod
    def get_version_strings(strs):
        versionRE = re.compile('\d+\.\d+(\.\d+)*(\-?[0-9a-zA-Z]+)?')

        # Return all unique matches
        versions = set()
        for s in strs:
            match = versionRE.search(s)
            if match != None:
                versions.add(match.group(0))

        return list(versions)
