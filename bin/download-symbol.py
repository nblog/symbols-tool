# -*- coding: utf-8 -*-

import os, sys, json, subprocess


def sym_path():
    try:
        return os.path.expandvars(
            json.load(open("sym_svr.json", encoding="utf-8-sig"))["path"]
        )
    except:
        return os.path.expandvars(os.path.join("%systemdrive%", "symbols"))


def sym_svr():
    try:
        return json.load(open("sym_svr.json", encoding="utf-8-sig"))["svr"]
    except:
        ''' dummy '''
        return [ "https://msdl.microsoft.com/download/symbols" ]


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
        print( 
            " ".join([
                "Use:", os.path.splitext(os.path.basename(__file__))[0],
                "pefile"])
        )
        sys.exit(1)


    pefile = sys.argv[1]

    if (not os.path.exists(pefile)):
        raise FileExistsError("\"{}\" does not exist".format(pefile))

    ''' symbol environ '''
    if ( not "_NT_SYMBOL_PATH" in os.environ ):
        os.environ["_NT_SYMBOL_PATH"] = \
            ";".join( \
            map(lambda svr: "SRV*{}*{}".format(sym_path(), svr), sym_svr()))

    ''' symbol info '''
    sys.exit(
        subprocess.call(" ".join(["RetrieveSymbols", pdb_info(pefile)]))
    )



if __name__ == "__main__":
    main()
