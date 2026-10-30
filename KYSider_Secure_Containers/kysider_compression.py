from collections import defaultdict, deque
import heapq
import os
import zlib
from kysider_security import (
    COMPRESSION_BLOCK_SIZE,
    MAX_CONTAINER_BYTES,
    MAX_EXPANSION_RATIO,
    MAX_PAYLOAD_BYTES,
    process_chunks_in_parallel,
)


_MAGIC = b"KYSC\x01"
_WINDOW_SIZE = 4096
_MAX_MATCH_LENGTH = 18
_MIN_MATCH_LENGTH = 3
_MAX_CANDIDATES = 64
_MAX_COMPRESSED_BLOCK_BYTES = COMPRESSION_BLOCK_SIZE + 64 * 1024


def _iter_lz77_tokens(data: bytes):
    positions = defaultdict(deque)
    indexed_positions = deque()
    position = 0

    while position < len(data):
        cutoff = position - _WINDOW_SIZE
        while indexed_positions and indexed_positions[0][0] < cutoff:
            expired_position, expired_key = indexed_positions.popleft()
            key_positions = positions[expired_key]
            if key_positions and key_positions[0] == expired_position:
                key_positions.popleft()
                if not key_positions:
                    del positions[expired_key]

        best_distance = 0
        best_length = 0
        if position + _MIN_MATCH_LENGTH <= len(data):
            key = data[position:position + _MIN_MATCH_LENGTH]
            candidates = positions.get(key, ())
            max_length = min(_MAX_MATCH_LENGTH, len(data) - position)

            for candidate in reversed(candidates):
                distance = position - candidate
                if distance > _WINDOW_SIZE:
                    break
                match_length = _MIN_MATCH_LENGTH
                while (
                    match_length < max_length
                    and data[candidate + match_length] == data[position + match_length]
                ):
                    match_length += 1
                if match_length > best_length:
                    best_distance = distance
                    best_length = match_length
                    if best_length == max_length:
                        break
                if len(candidates) > _MAX_CANDIDATES and position - candidate > 256:
                    break

        if best_length >= _MIN_MATCH_LENGTH:
            yield (True, best_distance, best_length)
            token_length = best_length
        else:
            yield (False, data[position], 1)
            token_length = 1

        for indexed_position in range(position, position + token_length):
            if indexed_position + _MIN_MATCH_LENGTH <= len(data):
                indexed_key = data[indexed_position:indexed_position + _MIN_MATCH_LENGTH]
                positions[indexed_key].append(indexed_position)
                indexed_positions.append((indexed_position, indexed_key))
        position += token_length


def _lz77_encode(data: bytes) -> bytes:
    encoded = bytearray()
    for is_match, value, length in _iter_lz77_tokens(data):
        if is_match:
            encoded.extend((1, value >> 8, value & 0xFF, length))
        else:
            encoded.extend((0, value))
    return bytes(encoded)


def _lz77_decode(data: bytes, expected_size: int) -> bytes:
    decoded = bytearray()
    position = 0
    while position < len(data):
        token_type = data[position]
        position += 1
        if token_type == 0:
            if position >= len(data):
                raise ValueError("Truncated LZ77 literal.")
            decoded.append(data[position])
            position += 1
        elif token_type == 1:
            if position + 3 > len(data):
                raise ValueError("Truncated LZ77 match.")
            distance = (data[position] << 8) | data[position + 1]
            length = data[position + 2]
            position += 3
            if distance == 0 or distance > len(decoded):
                raise ValueError("Invalid LZ77 distance.")
            if not _MIN_MATCH_LENGTH <= length <= _MAX_MATCH_LENGTH:
                raise ValueError("Invalid LZ77 match length.")
            if len(decoded) + length > expected_size:
                raise ValueError("LZ77 output exceeds its declared size.")
            for _ in range(length):
                decoded.append(decoded[-distance])
        else:
            raise ValueError("Unknown LZ77 token.")
        if len(decoded) > expected_size:
            raise ValueError("LZ77 output exceeds its declared size.")

    if len(decoded) != expected_size:
        raise ValueError("LZ77 output does not match its declared size.")
    return bytes(decoded)


def _lzss_encode(data: bytes) -> bytes:
    encoded = bytearray()
    tokens = iter(_iter_lz77_tokens(data))
    while True:
        group = []
        for _ in range(8):
            try:
                group.append(next(tokens))
            except StopIteration:
                break
        if not group:
            return bytes(encoded)

        flags = 0
        body = bytearray()
        for token_index, (is_match, value, length) in enumerate(group):
            if is_match:
                packed_match = ((value - 1) << 4) | (length - _MIN_MATCH_LENGTH)
                body.extend((packed_match >> 8, packed_match & 0xFF))
            else:
                flags |= 1 << token_index
                body.append(value)
        encoded.append(flags)
        encoded.extend(body)


def _lzss_decode(data: bytes, expected_size: int) -> bytes:
    decoded = bytearray()
    position = 0
    while len(decoded) < expected_size:
        if position >= len(data):
            raise ValueError("Truncated LZSS flag group.")
        flags = data[position]
        position += 1
        for flag_index in range(8):
            if len(decoded) >= expected_size:
                break
            if flags & (1 << flag_index):
                if position >= len(data):
                    raise ValueError("Truncated LZSS literal.")
                decoded.append(data[position])
                position += 1
                continue

            if position + 2 > len(data):
                raise ValueError("Truncated LZSS match.")
            packed_match = (data[position] << 8) | data[position + 1]
            position += 2
            distance = (packed_match >> 4) + 1
            length = (packed_match & 0x0F) + _MIN_MATCH_LENGTH
            if distance > len(decoded):
                raise ValueError("Invalid LZSS distance.")
            if len(decoded) + length > expected_size:
                raise ValueError("LZSS output exceeds its declared size.")
            for _ in range(length):
                decoded.append(decoded[-distance])

    if position != len(data):
        raise ValueError("Unexpected bytes after LZSS stream.")
    return bytes(decoded)


def _huffman_encode(data: bytes):
    frequencies = [0] * 256
    for value in data:
        frequencies[value] += 1

    heap = []
    order = 0
    for symbol, frequency in enumerate(frequencies):
        if frequency:
            heap.append((frequency, order, symbol))
            order += 1
    heapq.heapify(heap)

    if not heap:
        return bytes(256), b""

    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        heapq.heappush((heap), (left[0] + right[0], order, (left[2], right[2])))
        order += 1

    code_lengths = [0] * 256

    def assign_lengths(node, depth):
        if isinstance(node, int):
            code_lengths[node] = max(1, depth)
            return
        assign_lengths(node[0], depth + 1)
        assign_lengths(node[1], depth + 1)

    assign_lengths(heap[0][2], 0)

    canonical_codes = {}
    code = 0
    previous_length = 0
    for length, symbol in sorted(
        (length, symbol)
        for symbol, length in enumerate(code_lengths)
        if length
    ):
        code <<= length - previous_length
        canonical_codes[symbol] = (code, length)
        code += 1
        previous_length = length

    encoded_bits = bytearray()
    current_byte = 0
    bit_count = 0
    for value in data:
        symbol_code, length = canonical_codes[value]
        for shift in range(length - 1, -1, -1):
            current_byte = (current_byte << 1) | ((symbol_code >> shift) & 1)
            bit_count += 1
            if bit_count == 8:
                encoded_bits.append(current_byte)
                current_byte = 0
                bit_count = 0
    if bit_count:
        encoded_bits.append(current_byte << (8 - bit_count))

    return bytes(code_lengths), bytes(encoded_bits)


def _huffman_decode(code_lengths: bytes, data: bytes, expected_size: int) -> bytes:
    canonical_codes = []
    for symbol, length in enumerate(code_lengths):
        if length:
            canonical_codes.append((length, symbol))
    canonical_codes.sort()

    trie = {}
    code = 0
    previous_length = 0
    for length, symbol in canonical_codes:
        code <<= length - previous_length
        if code >= 1 << length:
            raise ValueError("Invalid Huffman code lengths.")
        node = trie
        for shift in range(length - 1, -1, -1):
            bit = (code >> shift) & 1
            if shift == 0:
                if bit in node:
                    raise ValueError("Conflicting Huffman code lengths.")
                node[bit] = symbol
            else:
                if bit in node and not isinstance(node[bit], dict):
                    raise ValueError("Conflicting Huffman code lengths.")
                node = node.setdefault(bit, {})
        code += 1
        previous_length = length

    if expected_size == 0:
        return b""
    if not trie:
        raise ValueError("Missing Huffman codes.")

    decoded = bytearray()
    node = trie
    for value in data:
        for shift in range(7, -1, -1):
            bit = (value >> shift) & 1
            if bit not in node:
                raise ValueError("Invalid Huffman bitstream.")
            node = node[bit]
            if not isinstance(node, dict):
                decoded.append(node)
                if len(decoded) == expected_size:
                    return bytes(decoded)
                node = trie
    raise ValueError("Truncated Huffman bitstream.")


def compress_payload(data: bytes) -> bytes:
    if len(data) > MAX_PAYLOAD_BYTES:
        raise ValueError("Payload exceeds the configured size limit.")
    raw_stream = _MAGIC + b"\x00" + len(data).to_bytes(8, "big") + data
    deflate_stream = zlib.compress(data, level=6)
    if len(data) > max(1, len(deflate_stream)) * MAX_EXPANSION_RATIO:
        return raw_stream
    compressed_stream = _MAGIC + b"\x02" + len(data).to_bytes(8, "big") + deflate_stream
    return compressed_stream if len(compressed_stream) < len(raw_stream) else raw_stream


def decompress_payload(data: bytes) -> bytes:
    if len(data) > MAX_CONTAINER_BYTES:
        raise ValueError("Compressed stream exceeds the configured size limit.")
    header_size = len(_MAGIC) + 1 + 8
    if len(data) < header_size or not data.startswith(_MAGIC):
        raise ValueError("Unknown KYSider compression stream.")

    mode = data[len(_MAGIC)]
    original_size = int.from_bytes(data[len(_MAGIC) + 1:header_size], "big")
    if original_size > MAX_PAYLOAD_BYTES:
        raise ValueError("Declared output exceeds the configured payload limit.")
    if mode == 0:
        raw_data = data[header_size:]
        if len(raw_data) != original_size:
            raise ValueError("Raw stream does not match its declared size.")
        return raw_data
    if mode == 2:
        compressed_data = data[header_size:]
        if not compressed_data or original_size > len(compressed_data) * MAX_EXPANSION_RATIO:
            raise ValueError("DEFLATE stream exceeds the expansion-ratio limit.")
        try:
            decompressor = zlib.decompressobj()
            decompressed = decompressor.decompress(compressed_data, original_size + 1)
        except zlib.error as error:
            raise ValueError("Invalid DEFLATE stream.") from error
        if (
            len(decompressed) > original_size
            or decompressor.unconsumed_tail
            or decompressor.unused_data
            or not decompressor.eof
        ):
            raise ValueError("DEFLATE stream exceeds its declared output size.")
        if len(decompressed) != original_size:
            raise ValueError("DEFLATE output does not match its declared size.")
        return decompressed
    if mode != 1:
        raise ValueError("Unknown KYSider compression mode.")

    extended_header_size = header_size + 16 + 256
    if len(data) < extended_header_size:
        raise ValueError("Truncated KYSider compression header.")
    lz77_size = int.from_bytes(data[header_size:header_size + 8], "big")
    lzss_size = int.from_bytes(data[header_size + 8:header_size + 16], "big")
    max_lz77_size = min(MAX_CONTAINER_BYTES, original_size * 2)
    max_lzss_size = min(MAX_CONTAINER_BYTES, lz77_size + (lz77_size + 7) // 8)
    huffman_data = data[extended_header_size:]
    if (
        lz77_size > max_lz77_size
        or lzss_size > max_lzss_size
        or lzss_size > max(1, len(huffman_data)) * MAX_EXPANSION_RATIO
    ):
        raise ValueError("Legacy compressed stream exceeds the configured size limit.")
    code_lengths = data[header_size + 16:extended_header_size]
    lzss_stream = _huffman_decode(code_lengths, huffman_data, lzss_size)
    lz77_stream = _lzss_decode(lzss_stream, lz77_size)
    return _lz77_decode(lz77_stream, original_size)


def _iter_file_chunks(source_file, expected_size: int):
    remaining = expected_size
    while remaining:
        chunk = source_file.read(min(COMPRESSION_BLOCK_SIZE, remaining))
        if not chunk:
            raise ValueError("Source stream ended before its declared size.")
        remaining -= len(chunk)
        yield chunk
    if source_file.read(1):
        raise ValueError("Source stream contains bytes after its declared size.")


def compress_file_blocks(source_path: str, destination_path: str) -> tuple[int, int, int]:
    source_size = os.path.getsize(source_path)
    if source_size <= 0 or source_size > MAX_PAYLOAD_BYTES:
        raise ValueError("Source archive size is empty or exceeds the configured payload limit.")
    block_count = (source_size + COMPRESSION_BLOCK_SIZE - 1) // COMPRESSION_BLOCK_SIZE

    def compress_block(_index: int, block: bytes) -> bytes:
        compressed = zlib.compress(block, level=6)
        return len(block).to_bytes(4, "big") + len(compressed).to_bytes(4, "big") + compressed

    with open(source_path, "rb") as source_file, open(destination_path, "wb") as output_file:
        actual_blocks = process_chunks_in_parallel(
            _iter_file_chunks(source_file, source_size),
            output_file,
            compress_block,
        )
    if actual_blocks != block_count:
        raise ValueError("Compressed block count did not match the source size.")
    compressed_size = os.path.getsize(destination_path)
    if compressed_size > MAX_CONTAINER_BYTES:
        raise ValueError("Compressed archive exceeds the configured container size limit.")
    return source_size, compressed_size, block_count


def _read_exact(source_file, size: int) -> bytes:
    data = source_file.read(size)
    if len(data) != size:
        raise ValueError("Compressed block stream is truncated.")
    return data


def _iter_compressed_blocks(source_file, block_count: int, uncompressed_size: int):
    remaining = uncompressed_size
    for _ in range(block_count):
        expected_block_size = min(COMPRESSION_BLOCK_SIZE, remaining)
        block_size = int.from_bytes(_read_exact(source_file, 4), "big")
        compressed_size = int.from_bytes(_read_exact(source_file, 4), "big")
        if (
            block_size != expected_block_size
            or compressed_size <= 0
            or compressed_size > _MAX_COMPRESSED_BLOCK_BYTES
        ):
            raise ValueError("Compressed block parameters are invalid.")
        compressed_block = _read_exact(source_file, compressed_size)
        remaining -= block_size
        yield block_size.to_bytes(4, "big") + compressed_block
    if remaining or source_file.read(1):
        raise ValueError("Compressed block stream size does not match its metadata.")


def decompress_file_blocks(
    source_path: str,
    destination_path: str,
    block_count: int,
    uncompressed_size: int,
):
    if (
        type(block_count) is not int
        or block_count <= 0
        or type(uncompressed_size) is not int
        or uncompressed_size <= 0
        or uncompressed_size > MAX_PAYLOAD_BYTES
        or block_count != (uncompressed_size + COMPRESSION_BLOCK_SIZE - 1) // COMPRESSION_BLOCK_SIZE
    ):
        raise ValueError("Compressed block metadata is invalid.")

    def decompress_block(_index: int, framed_block: bytes) -> bytes:
        block_size = int.from_bytes(framed_block[:4], "big")
        compressed = framed_block[4:]
        decompressor = zlib.decompressobj()
        try:
            output = decompressor.decompress(compressed, block_size + 1)
        except zlib.error as error:
            raise ValueError("Compressed block is invalid.") from error
        if (
            len(output) > block_size
            or decompressor.unconsumed_tail
            or decompressor.unused_data
            or not decompressor.eof
        ):
            raise ValueError("Compressed block exceeds its declared output size.")
        try:
            output += decompressor.flush()
        except zlib.error as error:
            raise ValueError("Compressed block is invalid.") from error
        if len(output) != block_size:
            raise ValueError("Decompressed block size does not match its declaration.")
        return output

    with open(source_path, "rb") as source_file, open(destination_path, "wb") as output_file:
        actual_blocks = process_chunks_in_parallel(
            _iter_compressed_blocks(source_file, block_count, uncompressed_size),
            output_file,
            decompress_block,
        )
    if actual_blocks != block_count or os.path.getsize(destination_path) != uncompressed_size:
        raise ValueError("Decompressed archive size does not match its metadata.")