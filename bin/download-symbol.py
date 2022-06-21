# -*- coding: utf-8 -*-

import os, sys, subprocess


def sym_path():
    return os.path.expandvars(os.path.join("%SystemDrive%", "symbols"))


def sym_svr():
    return [
        "https://msdl.microsoft.com/download/symbols",
        "https://chromium-browser-symsrv.commondatastorage.googleapis.com",
        "https://download.amd.com/dir/bin",
        "https://driver-symbols.nvidia.com/",
        "https://software.intel.com/sites/downloads/symbols/",
        "https://symbols.mozilla.org/",
    ]


def pdb_info(pefile):
    import lief, uuid

    info = lief.parse(pefile)

    assert(info.has_debug)

    debug_code_view = list(filter(lambda deb: deb.has_code_view, info.debug))

    assert(1 == len(debug_code_view))

    code_view = debug_code_view[0].code_view

    assert(code_view.cv_signature == lief.PE.CODE_VIEW_SIGNATURES.PDB_70)

    guid = "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(
        code_view.signature[3], code_view.signature[2], code_view.signature[1], code_view.signature[0],
        code_view.signature[5], code_view.signature[4], 
        code_view.signature[7], code_view.signature[6],
        code_view.signature[8], code_view.signature[9],
        code_view.signature[10], code_view.signature[11], code_view.signature[12], code_view.signature[13], code_view.signature[14], code_view.signature[15],
    )

    return "{}, {}, {}".format(guid.lower(), code_view.age, os.path.basename(code_view.filename))


def main():

    if (2 > len(sys.argv)):
        print( "Use: " + os.path.splitext(os.path.basename(__file__))[0] + " pefile" )
        sys.exit(1)

    assert( os.path.exists(sys.argv[1]) )

    ''' symbol environ '''
    if (not hasattr(os.environ, "_NT_SYMBOL_PATH")):
        os.environ["_NT_SYMBOL_PATH"] = ";".join( \
            map(lambda svr: "SRV*{}*{}".format(sym_path(), svr), sym_svr()))

    ''' symbol info '''
    cmd = pdb_info(sys.argv[1])

    sys.exit(
        subprocess.call("RetrieveSymbols " + cmd)
    )



if __name__ == "__main__":
    main()
