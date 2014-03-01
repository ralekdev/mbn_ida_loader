import idaapi
from idc import *
import struct

SBLImageFormatName = "Qualcomm SBL1 Image"
MBNImageFormatName = "Qualcomm MBN Image"

#
#   MBN header structure from LK in file target/msm8960/tools/mkheader.c
#

# -----------------------------------------------------------------------
def dwordAt(li, off):
    li.seek(off)
    s = li.read(4)
    if len(s) < 4: 
        return 0
    return struct.unpack('<I', s)[0]


# -----------------------------------------------------------------------
def accept_file(li, n):

    # we support only one format per file
    if n > 0:
        return 0

    # Pray nothing else has these first 8 bytes
    if dwordAt(li, 0) == 0x844BDCD1 and dwordAt(li, 4) == 0x73D71034:
        return SBLImageFormatName

    # check for regular MBN
    image_size  = dwordAt(li, 16)
    code_size   = dwordAt(li, 20)
    signature_size = dwordAt(li, 28)
    cert_chain_size = dwordAt(li, 36)

    if image_size == code_size + signature_size + cert_chain_size:
        return MBNImageFormatName
        
    
    # unrecognized format
    return 0

# -----------------------------------------------------------------------
def load_file(li, neflags, format):
    
    if format != MBNImageFormatName and format != SBLImageFormatName:
        Warning("Unknown format name: '%s'" % format)
        return 0

    idaapi.set_processor_type("arm:ARMv7-A&R", SETPROC_ALL|SETPROC_FATAL)

    if format == SBLImageFormatName:
        return load_file_sbl(li)
    elif format == MBNImageFormatName:
        return load_file_mbn(li)

    return 0

def load_file_sbl(li):

    start = 0
    if dwordAt(li, 8) == 0x7D0B435A:
        start = 0x2800

    image_source = dwordAt(li, start + 0x14)
    image_dest = dwordAt(li, start + 0x18)
    code_size = dwordAt(li, start + 0x20)

    header_size = 80

    load_addr = image_dest

    if not load_segment(li, start, header_size, load_addr - header_size, "HEADER", "CONST"):
        return 0

    if not load_segment(li, image_source, code_size, load_addr, "CODE", "CODE", "VECTOR_RESET"):
        return 0

    find_sbl_segs(load_addr, load_addr+code_size)
    return 1


def find_aboot_segs(image_dest):

    inst = DecodeInstruction(image_dest)
    reset_func = image_dest
    if inst.get_canon_mnem() == 'B':
        reset_func = inst.Op1.addr

    search_start = reset_func
    search_end = search_start + 0x100

    data_insts = FindBinary(search_start, SEARCH_DOWN, "4C 00 ?? ?? 4C 10 ?? ?? 4C 20 ?? ??")
    if data_insts == BADADDR or data_insts > search_end:
        return False

    data_start = Dword(DecodeInstruction(data_insts + 4).Op2.addr)
    data_end = Dword(DecodeInstruction(data_insts + 8).Op2.addr)
    data_end = (data_end + 3) & ~3

    AddSeg(data_start, data_end, 0, 1, idaapi.saRelPara, idaapi.scPub)
    SetSegClass(data_start, "DATA")
    RenameSeg(data_start, "DATA")

    bss_insts = FindBinary(data_insts, SEARCH_DOWN, "34 00 ?? ?? 34 10 ?? ??")
    if bss_insts == BADADDR or bss_insts > search_end:
        return False

    bss_start = Dword(DecodeInstruction(bss_insts + 0).Op2.addr)
    bss_end = Dword(DecodeInstruction(bss_insts + 4).Op2.addr)

    AddSeg(bss_start, bss_end, 0, 1, idaapi.saRelPara, idaapi.scPub)
    SetSegClass(bss_start, "BSS")
    RenameSeg(bss_start, "BSS")

    kmain_addr = FindBinary(bss_insts, SEARCH_DOWN, "?? ?? 00 FA")
    if kmain_addr == BADADDR or kmain_addr > search_end:
        return False

    kmain_addr = DecodeInstruction(kmain_addr).Op1.addr
    MakeName(kmain_addr, "kmain")
    idaapi.add_entry(kmain_addr, kmain_addr, "kmain", 1)
    return True

def find_sbl_segs_regex(load_addr, load_end):
    load_byte = load_addr >> 24

    pat = "?? ?? ?? %02x ?? ?? ?? %02x ?? ?? 00 00 ?? ?? ?? %02x ?? ?? ?? 00" % (load_byte,load_byte,load_byte)

    addr = FindBinary(load_end, SEARCH_UP, pat)
    while addr != BADADDR:
        img_load_addr = Dword(addr+0)
        img_data_base = Dword(addr+4)
        img_data_len = Dword(addr+8)
        img_bss_base = Dword(addr+12)
        img_bss_len = Dword(addr+16)

        if img_load_addr >= load_addr and \
            img_data_base >= load_addr and \
            img_load_addr < load_end and  \
            img_bss_base >= img_data_base and \
            img_data_base + img_data_len == img_bss_base:
            
            AddSeg(img_data_base, img_data_base+img_data_len, 0, 1, idaapi.saRelPara, idaapi.scPub)
            SetSegClass(img_data_base, "DATA")
            RenameSeg(img_data_base, "DATA")

            AddSeg(img_bss_base, img_bss_base+img_bss_len, 0, 1, idaapi.saRelPara, idaapi.scPub)
            SetSegClass(img_bss_base, "BSS")
            RenameSeg(img_bss_base, "BSS")
            return True
            
        # Don't want to skip anything, so move back up 16 bytes (pattern is 20 bytes)
        addr = FindBinary(addr + 16, SEARCH_UP, pat)

    return False

def find_sbl_segs(load_addr, load_end):
    print "Trying to find SBL segments"

    if find_sbl_segs_regex(load_addr, load_end):
        return True

    print "Find by regex failed, brute-forcing..."
    def brute_force(addr):
        img_load_addr = Dword(addr+0)
        img_data_base = Dword(addr+4)
        img_data_len = Dword(addr+8)
        img_bss_base = Dword(addr+12)
        img_bss_len = Dword(addr+16)
        
        if img_load_addr < load_addr or img_data_base < load_addr or img_load_addr > load_end:
            return False

        if img_bss_base < load_addr or img_bss_base < img_data_base:
            return False

        if img_data_base + img_data_len != img_bss_base:
            return False

        print "Load %X" % (img_load_addr)
        print "RW (%X - %X)" % (img_data_base, img_data_base + img_data_len)
        print "ZI (%X - %X)" % (img_bss_base, img_bss_base + img_bss_len)
        
        AddSeg(img_data_base, img_data_base+img_data_len, 0, 1, idaapi.saRelPara, idaapi.scPub)
        SetSegClass(img_data_base, "DATA")
        RenameSeg(img_data_base, "DATA")

        AddSeg(img_bss_base, img_bss_base+img_bss_len, 0, 1, idaapi.saRelPara, idaapi.scPub)
        SetSegClass(img_bss_base, "BSS")
        RenameSeg(img_bss_base, "BSS")

        return True

    # take a guess and start looking halfway through
    pos = load_addr + (load_end - load_addr)/2
    while pos < (load_end - 20):
        ok = brute_force(pos)
        if ok:
            return True
        pos += 4

    return False

def find_segs(load_addr, load_end):
    if not find_aboot_segs(load_addr):
        find_sbl_segs(load_addr, load_end)

def load_file_mbn(li):
    image_source = dwordAt(li, 8)
    image_dest = dwordAt(li, 12)
    code_size = dwordAt(li, 20)

    header_size = 40

    # do they still have this?
    HTC_HDDR_BASE = 72
    if dwordAt(li, HTC_HDDR_BASE) == 0x52444448: # HDDR
        # HTC TZ extra header to load an additional segment
        htc_load_addr = dwordAt(li, HTC_HDDR_BASE + 4)
        htc_image_size = dwordAt(li, HTC_HDDR_BASE+ 8)
        htc_image_src = dwordAt(li, HTC_HDDR_BASE + 12)
        htc_start = htc_image_src - image_source + header_size - image_dest
        load_segment(li, htc_start, htc_image_size, htc_load_addr, "TZ2", "CODE")

        code_size -= htc_image_size

    load_addr = image_dest - image_source

    if not load_segment(li, 0, header_size, load_addr - header_size, "HEADER", "CONST"):
        return 0

    if not load_segment(li, header_size, code_size, load_addr, "CODE", "CODE", "VECTOR_RESET"):
        return 0

    find_segs(load_addr, load_addr + code_size)

    return 1


def load_segment(li, file_ofs, code_size, load_addr, seg_name = "CODE", seg_class = "CODE", entry_name = None):
    load_end = load_addr + code_size

    AddSeg(load_addr, load_end, 0, 1, idaapi.saRelPara, idaapi.scPub)
    SetSegClass(load_addr, seg_class)
    RenameSeg(load_addr, seg_name)

    # copy bytes to the database
    li.file2base(file_ofs, load_addr, load_end, 0)

    if entry_name is not None:
        idaapi.add_entry(load_addr, load_addr, entry_name, 1)

    return 1

# -----------------------------------------------------------------------
def move_segm(frm, to, sz, fileformatname):
    Warning("move_segm(from=%s, to=%s, sz=%d, formatname=%s" % (hex(frm), hex(to), sz, fileformatname))
    return 0

