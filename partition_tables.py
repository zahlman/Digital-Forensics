import uuid


def parse_mbr(mbr_bytes: bytes) -> list[dict]:
    par_entries = []
    entry_number = 0

    for i in range(0x1BE, 0x1FE, 16):
        entry_data = mbr_bytes[i : i + 16]
        start_sector = int.from_bytes(entry_data[8:12], byteorder="little")
        end_sector = start_sector + int.from_bytes(entry_data[12:16], byteorder="little") - 1
        partition_type = f"{hex(entry_data[4])}"

        # order is different in tests than in documentation
        # here's the order from test file that brian provided -
        # [{"type": "0x6", "end": 3913727, "start": 32, "number": 0}]

        if partition_type != "0x0":
            partition_entry = {
                "type": partition_type,
                "end": end_sector,
                "start": start_sector,
                "number": entry_number,
            }
            par_entries.append(partition_entry)
            entry_number += 1
            # print(partition_entry)
    print(par_entries)
    return par_entries


## the test
# "start": 40,
# "end": 409639,
# "number": 0,
# "name": "EFI system partition",
# "type": UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),


def parse_gpt(gpt_file, sector_size: int = 512) -> list[dict]:
    entries = []

    # skipping fake mbr
    # pdb.set_trace()
    gpt_file.read(sector_size)

    # the gpt header to get start sector
    gpt_header = gpt_file.read(sector_size)
    start_sector = int.from_bytes(gpt_header[0x48:0x50], byteorder="little")
    num_entries = 0

    for i in range(1, start_sector):
        partition_table = gpt_file.read(sector_size)

    while partition_table != None:
        for i in range(0, len(partition_table), 128):
            entry_data = partition_table[i : i + 128]
            start = int.from_bytes(entry_data[0x20:0x28], byteorder="little")
            if start == 0:
                # means all zero partition entries after this
                partition_table = None
                return entries

            end = int.from_bytes(entry_data[0x28:0x30], byteorder="little")
            type = uuid.UUID(bytes_le=entry_data[0:16])

            # brian's way of doing it
            val = entry_data[56:128].decode("utf-16-le")
            end_index = val.find("\x00")
            name = val[0:end_index]

            entry = {
                "start": start,
                "end": end,
                "number": num_entries,
                "name": name,
                "type": type,
            }

            print(entry)
            entries.append(entry)
            num_entries += 1

        partition_table = gpt_file.read(sector_size)  # reading the next sector

    return entries


# if __name__ == "__main__":
