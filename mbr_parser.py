import os
import sys
import struct

PARTITION_TYPE_LIST = {
    # The page that getting this list
    # lnk: http://forensic-proof.com/archives/435
    0x00: 'Empty',
    0x01: 'DOS 12-bit FAT',
    0x02: 'XENIX root file system',
    0x03: 'XENIX /usr file system (obsolete)',
    0x04: 'DOS 16-bit FAT (up to 32M)',
    0x05: 'DOS 3.3+ extended partition',
    0x06: 'DOS 3.31+ Large File System (16-bit FAT, over 32M)',
    0x07: 'Advanced Unix | exFAT | OS/2 HPFS | Windows NT NTFS',
    0x08: 'OS/2 (v1.0-1.3 only) | AIX bootable partition, SplitDrive | Commodore Dos | DELL partition spanning multiple drives',
    0x09: 'AIX data partition',
    0x0A: 'OPUS | Coherent swap partition | OS/2 Boot Manager',
    0x0B: 'Windows 95 with 32-bit FAT',
    0x0C: 'Windows 95 with 32-bit FAT (using LBA-mode INT 13 extensions)',
    0x0E: 'VFAT logical-block-addressable VFAT (same as 06h but using LBA)',
    0x0F: 'Extended LBA partition (same as 05h but using LBA)',
    0x10: 'OPUS',
    0x11: 'FAT12 OS/2 Boot Manager hidden 12-bit FAT partition',
    0x12: 'Compaq Diagnostics partition',
    0x14: 'FAT16 OS/2 Boot Manager hidden sub-32M 16-bit FAT partition',
    0x16: 'FAT16 OS/2 Boot Manager hidden over-32M 16-bit FAT partition',
    0x17: 'OS/2 Boot Manager hidden HPFS partition | hidden NTFS partition',
    0x18: 'ASTSuspend AST special Windows swap file (“Zoro-Volt Suspend” partition)',
    0x19: 'Willowtech Willowtech Photon coS',
    0x1B: 'Windows hidden Windows95 FAT32 partition',
    0x1C: 'Windows hidden Windows 95 FAT32 partition (LBA-mode)',
    0x1E: 'Windows hidden LBA VFAT partition',
    0x20: 'Willowsoft Overture File System (OFS1)',
    0x21: '[reserved] officially listed as reserved | FSo2',
    0x23: '[reserved] officially listed as reserved',
    0x24: 'NEC MS-DOS 3.x',
    0x26: '[reserved] officially listed as reserved',
    0x31: '[reserved] officially listed as reserved',
    0x33: '[reserved] officially listed as reserved',
    0x34: '[reserved] officially listed as reserved',
    0x36: '[reserved] officially listed as reserved',
    0x38: 'Theos',
    0x3C: 'PowerQuest PartitionMagic recovery partition',
    0x40: 'VENIX 80286',
    0x41: 'Personal RISC Boot | PowerPC boot partition',
    0x42: 'SFS(Secure File System) by Peter Gutmann',
    0x45: 'EUMEL/Elan',
    0x46: 'EUMEL/Elan',
    0x47: 'EUMEL/Elan',
    0x48: 'EUMEL/Elan',
    0x4F: 'Obron boot/data partition',
    0x50: 'OnTrack Disk Manager, read-only partition',
    0x51: 'OnTrack Disk Manager, read/write partition | NOVELL',
    0x52: 'CP/M | Microport System V/386',
    0x53: 'OnTrack Disk Manager, write-only partition',
    0x54: 'OnTrack Disk Manager (DDO)',
    0x55: 'EZ-Drive (see also INT 13/AH=FFh “EZ-Drive”)',
    0x56: 'GoldenBow VFeature',
    0x5C: 'Priam EDISK',
    0x61: 'SpeedStor',
    0x63: 'Unix SysV/386, 386/ix | Mach, MtXinu BSD 4.3 on Mach | GNU-HURD',
    0x64: 'Novell Netware 286 | SpeedStore',
    0x65: 'Novell NetWare (3.11)',
    0x67: 'Novell',
    0x68: 'Novell',
    0x69: 'Novell NSS Volume',
    0x70: 'DiskSecure Multi-Boot',
    0x71: '[reserved] officially listed as reserved',
    0x73: '[reserved] officially listed as reserved',
    0x74: '[reserved] officially listed as reserved',
    0x75: 'PC/IX',
    0x76: '[reserved] officially listed as reserved',
    0x7E: 'F.I.X',
    0x80: 'Minix v1.1 – 1.4a',
    0x81: 'Minix v1.4b+ | Linux | Mitac Advanced Disk Manager',
    0x82: 'Linux Swap partition | Prime | Solaris (Unix)',
    0x83: 'Linux native file system (ex2fs/xiafs)',
    0x84: 'DOS OS/2-renumbered type 04h partition (hiding DOS C: drive)',
    0x85: 'Linux EXT',
    0x86: 'FAT16 volume/stripe set (Windows NT)',
    0x87: 'HPFS Fault-Tolerant mirrored partition | NTFS volume/stripe set',
    0x93: 'Amoeba file system',
    0x94: 'Amoeba bad block table',
    0x98: 'Datalight ROM-DOS SuperBoot',
    0x99: 'Mylex EISA SCSI',
    0xA0: 'Phoenix NoteBIOS Power Management “Save-to-Disk” partition',
    0xA1: '[reserved] officially listed as reserved',
    0xA3: '[reserved] officially listed as reserved',
    0xA4: '[reserved] officially listed as reserved',
    0xA5: 'FreeBSD, BSD/386',
    0xA6: 'OpenBSD',
    0xA9: 'NetBSD',
    0xB1: '[reserved] officially listed as reserved',
    0xB3: '[reserved] officially listed as reserved',
    0xB4: '[reserved] officially listed as reserved',
    0xB6: '[reserved] officially listed as reserved | Windows NT mirror set (master), FAT16 file system',
    0xB7: 'BSDI file system (secondarily swap) | Windows NT mirror set (master), NTFS file system',
    0xB8: 'BSDI swap partition (secondarily file system)',
    0xBE: 'Solaris boot partition',
    0xC0: 'CTOS | DR-DOS/Novell DOS secured partition',
    0xC1: 'DR-DOS6.0 LOGIN.EXE-secured 12-bit FAT partition',
    0xC4: 'DR-DOS6.0 LOGIN.EXE-secured 16-bit FAT partition',
    0xC6: 'DR-DOS6.0 LOGIN.EXE-secured 12-bit Huge partition | corrupted FAT16 volume/stripe set (Windows NT) | Windows NT mirror set (slave), FAT16 file system',
    0xC7: 'Syurinx Boot | corrupted NTFS volume/stripe set | Windows NT mirror set (slave), NTFS file system',
    0xCB: 'DR-DOS/OpenDOS secured FAT32',
    0xCC: 'DR-DOS secured FAT32 (LBA)',
    0xCE: 'DR-DOS secured FAT16 (LBA)',
    0xD0: 'Multiuser DOS secured FAT12',
    0xD1: 'Old Multiuser DOS secured FAT12',
    0xD4: 'Old Multiuser DOS secured FAT16 (<=32M)',
    0xD5: 'Old Multiuser DOS secured extended partition',
    0xD6: 'Old Multiuser DOS secured FAT16 (>32M)',
    0xD8: 'CP/M-86 | Concurrent CP/M, Concurrent DOS | CTOS (Convergent Technologies OS)',
    0xE1: 'SpeedStor 12-bit FAT extended partition',
    0xE2: 'DOS read-only (Florian Painke’s XFDISK 1.0.4)',
    0xE3: 'DOS read-only | Storage Dimensions',
    0xE4: 'SpeedStor 16-bit FAT extended partition',
    0xE5: '[reserved] officially listed as reserved',
    0xE6: '[reserved] officially listed as reserved',
    0xEB: 'BeOS BFS (BFS1)',
    0xF1: 'Storage Dimensions',
    0xF2: 'DOS 3.3+ secondary partition',
    0xF3: '[reserved] officially listed as reserved',
    0xF4: 'SpeedStor | Storage Dimensions',
    0xF5: 'Prologue',
    0xF6: '[reserved] officially listed as reserved',
    0xFB: 'VMware partition',
    0xFE: 'LANstep | IBM PS/2 IML (Initial Microcode Load) partition',
    0xFF: 'Xenix bad block table | VMware raw partition'
}

class PartitionEntry:
    _default_sector_size = 512

    def __init__(self, partition_table_bytes: bytes):
        self.boot_indicator = partition_table_bytes[0]
        self.start_chs_address = self.bytes_to_chs(partition_table_bytes[1 : 4])
        self.partition_type = partition_table_bytes[4]
        self.end_chs_address = self.bytes_to_chs(partition_table_bytes[5 : 8])
        self.start_lba_address = int.from_bytes(partition_table_bytes[8 : 12], 'little')
        self.total_sectors = int.from_bytes(partition_table_bytes[12 : 16], 'little')
    
    def bytes_to_chs(self, b: bytes):
        chs_int = int.from_bytes(b, 'little')
        c = (chs_int & 0b111111111100000000000000) >> 14 # upper 10 bits
        h = (chs_int & 0b000000000011111111000000) >> 6 # middle 8 bits
        s = (chs_int & 0b000000000000000000111111) # under 6 bits

        return c, h, s

    def is_boot(self):
        return self.boot_indicator == 0x80
    
    def get_partition_type_name(self):
        global PARTITION_TYPE_LIST
        return PARTITION_TYPE_LIST[self.partition_type]

    def get_size(self):
        return self._default_sector_size * self.total_sectors

class Mbr:
    _partition_table = []

    def __init__(self, mbr_bytes: bytes):
        self._bootcode_bytes = mbr_bytes[0 : 446]
        self._partition_table_bytes = mbr_bytes[446 : 510]
        self._signature_bytes = mbr_bytes[510 : 512]

        for i in range(0, len(self._partition_table_bytes), 16):
            self._partition_table.append(PartitionEntry(self._partition_table_bytes[i : i+16]))

        self.signature = self._signature_bytes.hex().upper()
    
    def verify_signature(self):
        return self._signature_bytes == b'\x55\xAA'
    
    def get_all_partition_entry(self):
        return tuple(self._partition_table)
    
    def get_partition_entry(self, n):
        return self._partition_table[n]



if __name__ == '__main__':
    if not len(sys.argv) == 2:
        print('Usage: {} <mbr image path>'.format(sys.argv[0]))
        exit(0)
    mbr_file_path = sys.argv[1]

    if not os.path.exists(mbr_file_path):
        print('{} not found'.format(mbr_file_path), file=sys.stderr)
        exit(0)
    
    if os.path.getsize(mbr_file_path) < 512:
        print('{} is smaller than 512 bytes'.format(mbr_file_path), file=sys.stderr)
        exit(0)
    
    with open(mbr_file_path, 'rb') as f:
        mbr = Mbr(f.read(512))

        for partition in mbr.get_all_partition_entry():
            print('Partition type:', partition.get_partition_type_name())
            print('CHS address: {} ~ {}'.format(partition.start_chs_address, partition.end_chs_address))
            print('LBA address:', partition.start_lba_address)
            print('Total sectors:', partition.total_sectors)
            print('Total size: {:.1f} GB'.format(partition.get_size() / 1024 / 1024 / 1024))
            print('Boot:', 'yes' if partition.is_boot() else 'no')
            print()