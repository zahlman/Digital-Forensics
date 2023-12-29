import argparse
import typing

from ntfs_utils import (
    apply_fixup,
    attr_to_string,
    file_name_to_str,
    get_attr_by_id,
    header_to_str,
    parse_time,
    std_info_to_str,
)

order_literal = typing.Union[typing.Literal["little"], typing.Literal["big"]]


def unpack(data: bytes, signed=False, byteorder: order_literal = "little") -> int:
    """Unpack a single value from bytes"""

    return int.from_bytes(data, byteorder=byteorder, signed=signed)


class ParseMFT:
    def __init__(self, file):
        self.file = file
        self.file.seek(0)
        boot = self.file.read(512)
        bytes_per_sector = unpack(boot[11:13])
        sectors_per_cluster = unpack(boot[13:14])
        mft_start = unpack(boot[48:56])
        self.mft_byte_offset = mft_start * sectors_per_cluster * bytes_per_sector
        self.bytes_per_entry = 1024  # assume 1024 byte entries

    def parse_entry_header(self, address: int, entry: bytes) -> dict:
        """Parse the header of the MFT entry.

        input:
            address: the address of the entry
            entry: the bytes of the entry
        returns:
            dict: {
                'address': int, (same as input)
                'sequence': int, (the sequence value)
                'logfile_seq_num': int, (the log sequence number)
                'links': int, (the link count)
                'allocated': bool, (whether the entry is allocated)
            }

        """
        # fill this in
        sequence = unpack(entry[16:18])
        logfile_seq_num = unpack(entry[8:16])
        links = unpack(entry[18:20])
        allocated = True if entry[22] else False

        return {
            "address": address,
            "sequence": sequence,
            "logfile_seq_num": logfile_seq_num,
            "links": links,
            "allocated": allocated,
        }
        # pass

    def parse_std_info_attr(self, entry: bytes, entry_start: int = 0x38) -> dict:
        """Parse the standard_information attribute of an MFT entry.

        input:
            entry: bytes, the MFT entry to parse
            entry_start: int, the offset of the first byte of the attribute
        output:
            dict{
                'created': string, (the creation time)
                'modified': string, (the modification time)
                'mft_modified': string, (the MFT modified time)
                'accessed': string, (the last access time)
                'flags': string, (the flags)
                'std_info_size': int, (the size of the attribute)
                'std_info_end': int, (the offset of the next attribute)
            }
        See tabls 13.5 and 13.3 etc.
        """

        attribute, std_info_end = get_attr_by_id(0x10, entry, entry_start)
        # fill this in
        # offset = unpack(attribute[20:22])
        content = attribute[24:]
        created = parse_time(attribute, (0, 8))
        modified = parse_time(attribute, (8, 16))
        mft_modified = parse_time(attribute, (16, 24))
        accessed = parse_time(attribute, (24, 32))
        flags = unpack(content[32:36])
        std_info_size = unpack(attribute[16:20])

        return {
            "created": created,
            "modified": modified,
            "mft_modified": mft_modified,
            "accessed": accessed,
            "flags": flags,
            "std_info_size": std_info_size,
            "std_info_end": std_info_end,
        }
        # pass

    def parse_file_name_attr(self, entry: bytes, prev_entry_end: int) -> dict:
        """Parse the file_name attribute of an MFT entry.

        input:
            entry: bytes, the MFT entry to parse
            prev_entry_end: int, the offset of the last byte of the previous attribute
        output:
            dict{
                'name': str, (the name of the file)
                'parent': int, (the parent directory)
                'sequence': int, (the sequence number)
                'allocated_size': int, (the allocated size)
                'actual_size': int, (the actual size)
                'created': int, (the creation time)
                'modified': int, (the modification time)
                'mft_modified': int, (the MFT modified time)
                'accessed': int, (the last access time)
                'flags': int, (the flags)
                'file_name_size': int, (the size of the attribute)
                'file_name_end': int, (the offset of the next attribute)
            }
        """
        attribute, file_name_end = get_attr_by_id(0x30, entry, prev_entry_end)
        # fill this in
        # You'll need to call .decode("utf-16-le").strip(" ") on the bytes
        # representing the name

        content = attribute[24:]
        name_length = unpack(content[64:65])

        file_name_size = 66 + 2 * name_length
        name = content[66:file_name_size].decode("utf-16-le").strip(" ")
        parent = unpack(content[0:6])
        sequence = unpack(content[6:8])
        allocated_size = unpack(content[40:48])
        actual_size = unpack(content[48:56])
        created = parse_time(attribute, (8, 16))
        modified = parse_time(attribute, (16, 24))
        mft_modified = parse_time(attribute, (24, 32))
        accessed = parse_time(attribute, (32, 40))
        flags = unpack(content[56:60])

        return {
            "name": name[:name_length],
            "parent": parent,
            "sequence": sequence,
            "allocated_size": allocated_size,
            "actual_size": actual_size,
            "created": created,
            "modified": modified,
            "mft_modified": mft_modified,
            "accessed": accessed,
            "flags": flags,
            "file_name_size": file_name_size,
            "file_name_end": file_name_end,
        }

    def parse_data_attr(self, entry: bytes, prev_attr_end: int) -> dict:
        """Parse the data attribute of an MFT entry.

        input:
            entry: bytes, the MFT entry to parse
            prev_attr_end: int, the offset of the last byte of the previous attribute
        output:
            if the entry is resident:
            dict:
                type: 0x80, (the type code of the attribute)
                size: int, (the size of the attribute)

            if the entry is non-resident, the follow keys are added:
                init_size: int, (the size of the attribute before it was compressed)
                sector_list: list, (the list of non-resident sectors)

        """
        attribute, attr_end = get_attr_by_id(0x80, entry, prev_attr_end)
        # fill this in
        # see table 13.4 etc for non-resident entries.
        size_resident = unpack(attribute[16:20])  # this is wrong for non-resident entry
        is_non_resident = True if unpack(attribute[8:9]) else False
        if not is_non_resident:
            return {"type": 0x80, "size": size_resident}

        init_size = unpack(attribute[48:56])

        offset_runlist = unpack(attribute[32:34])
        print("offset runlist", offset_runlist)
        sector_list = []
        cluster_offset = 0
        # while(True):
        while True:
            single_byte = attribute[offset_runlist]
            print("single_byte", single_byte)

            low = single_byte & 0x0F  # number of bytes in run length
            print("low", low)

            high = (single_byte & 0xF0) >> 4
            print("high", high)

            if low == 0 and high == 0:
                break

            length = unpack(attribute[offset_runlist + 1 : offset_runlist + low + 1])
            print("length", length)
            cluster_offset = cluster_offset + unpack(
                attribute[offset_runlist + 1 + low : (offset_runlist + 1 + low) + high]
            )
            print("cluster_offset", cluster_offset)
            # First time 1666
            # Second time 1718 != 94

            for x in range(cluster_offset, cluster_offset + length):
                sector_list.append(x)
            print("before offset", offset_runlist)
            offset_runlist = offset_runlist + low + high + 1
            print("next offset", offset_runlist)

        print(sector_list)
        return {"type": 0x80, "size": init_size, "init_size": init_size, "sector_list": sector_list}

    def istat_entry(self, address: int) -> dict:
        """Parse the header, std_info, file_name, and data attributes of an MFT entry.

        input:
            address: int, the address of the MFT entry (e.g., 0 is the MFT itself)
        output:
            dict:
                'header': dict, from parse_entry_header()
                'std_info': dict, from parse_std_info()
                'file_name': dict, from parse_file_name()
                'data': dict, from parse_data_attr()
        """
        # assumes contiguous MFT
        self.file.seek(self.mft_byte_offset + address * self.bytes_per_entry)
        entry = self.file.read(1024)
        entry = apply_fixup(entry)

        # fill this in
        # parse the header
        header_entry = self.parse_entry_header(address, entry)

        # parse std_info attribute (fill this in)
        std_info = self.parse_std_info_attr(entry)

        # parse filename attribute (fill this in)
        file_name = self.parse_file_name_attr(entry, std_info["std_info_end"])

        # parse the data attribute (fill this in)
        data = self.parse_data_attr(entry, file_name["file_name_end"])

        # return the dictionary
        return {"header": header_entry, "std_info": std_info, "file_name": file_name, "data": data}

    def print_istat_entry(self, istat_entry: dict):
        """Print the istat entry to the screen.
        This is filled in for you. No worked needed.
        """
        data_attr = istat_entry["data"]
        file_name_attr = istat_entry["file_name"]
        std_info_attr = istat_entry["std_info"]
        header_entry = istat_entry["header"]

        result = (
            header_to_str(header_entry)
            + std_info_to_str(std_info_attr)
            + file_name_to_str(file_name_attr)
            + "\nAttributes:\n"
            + attr_to_string(0x10, std_info_attr["std_info_size"])
            + attr_to_string(0x30, file_name_attr["file_name_size"])
        )
        if "init_size" in data_attr:
            result += attr_to_string(0x80, data_attr["size"], data_attr["init_size"])
        else:
            result += attr_to_string(0x80, data_attr["size"])
        if "sector_list" in data_attr:
            result += "\n"
            sector_list = data_attr["sector_list"]
            for x in range(0, len(sector_list), 8):
                result += " ".join([str(x) for x in sector_list[x : x + 8]]) + "\n"
        return result


def main():
    """Argument Parsing"""

    # This is all filled in. No work needed here.
    parser = argparse.ArgumentParser(description="Display details of the NTFS MFT entry.")
    parser.add_argument("image", help="Path to an NTFS raw (dd) image")
    parser.add_argument("address", type=int, help="MFT entry number to display stats on")
    args = parser.parse_args()

    with open(args.image, "rb") as fd:
        ntfs = ParseMFT(fd)
        result = ntfs.istat_entry(args.address)
        print(ntfs.print_istat_entry(result))


if __name__ == "__main__":
    main()
