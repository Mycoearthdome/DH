#!/usr/bin/env python3
import hashlib
import sys
from bitarray import bitarray
import lzma
import zlib
from os import remove
from os.path import getsize
from io import BytesIO

def auto_curve_length(file_size: int) -> int:
    """Pick an appropriate curve length based on input file size."""
    if file_size < 1 * 1024 * 1024:        # <1 MB
        return 512
    elif file_size < 50 * 1024 * 1024:     # <50 MB
        return 4096
    elif file_size < 500 * 1024 * 1024:    # <500 MB
        return 8192
    else:                                  # >=500 MB
        return 16384

# -----------------------------
# Deterministic DH-style curve generation (fast)
# -----------------------------
def generate_dh_curve_fast(length: int, seed: bytes, index: int) -> bitarray:
    """
    Generate `length` bits deterministically using SHA256 digests in blocks.
    Each SHA256 digest gives 256 bits (32 bytes). We concatenate digests until
    we have at least `length` bits, then trim.
    """
    curve = bitarray()
    counter = 0
    while len(curve) < length:
        digest = hashlib.sha256(seed + index.to_bytes(4, 'big') + counter.to_bytes(4, 'big')).digest()
        block_bits = bitarray()
        block_bits.frombytes(digest)   # 256 bits
        curve.extend(block_bits)
        counter += 1
    # trim to exact length
    return curve[:length]

# -----------------------------
# Compression helpers (LZMA for payload)
# -----------------------------
def compress_payload(payload_bytes: bytes) -> bytes:
    return lzma.compress(payload_bytes, preset=9 | lzma.PRESET_EXTREME)

def decompress_payload(compressed_bytes: bytes) -> bytes:
    return lzma.decompress(compressed_bytes)

# -----------------------------
# Streaming encode (no curve storage) + final zlib compress (uses temp file)
# -----------------------------
def encode_file_stream(input_path: str, seed: bytes, curve_length: int, output_path: str):
    # Read input
    with open(input_path, "rb") as fin:
        payload_bytes = fin.read()

    # LZMA-compress payload first
    lzma_compressed = compress_payload(payload_bytes)

    # Compute SHA-256 of the compressed payload for verification at decode
    payload_hash = hashlib.sha256(lzma_compressed).digest()  # 32 bytes

    # Convert compressed payload to bits (one time)
    payload_bits_total = bitarray()
    payload_bits_total.frombytes(lzma_compressed)
    payload_bit_len = len(payload_bits_total)

    per_curve_lengths = []
    curve_index = 0
    pointer = 0

    temp_path = output_path + ".tmp"

    # Create temporary uncompressed stream (so we can write header first then lengths at end)
    with open(temp_path, "wb") as fout:
        # Header placeholder: 16 bytes + 32 bytes SHA256 (total 48 bytes)
        fout.write(b'\x00' * 48)

        # Encode curve-by-curve (fast curve generation + inline injection)
        encoded_chunk_byte_len = (curve_length + 7) // 8
        while pointer < payload_bit_len:
            curve_bits = generate_dh_curve_fast(curve_length, seed, curve_index)
            # Count how many zeros (available payload bit slots)
            zeros_in_curve = curve_bits.count(0)

            # Inline inject directly from payload_bits_total starting at pointer
            encoded_chunk = bitarray(curve_length)
            payload_index = 0  # how many payload bits we consumed this curve

            # Local quick references for speed
            pb = payload_bits_total
            total_bits = payload_bit_len

            for i in range(curve_length):
                if curve_bits[i] == 0:
                    src_pos = pointer + payload_index
                    if src_pos < total_bits:
                        encoded_chunk[i] = pb[src_pos]
                        payload_index += 1
                    else:
                        encoded_chunk[i] = 0
                else:
                    # set bit to 1 where the curve had a 1
                    encoded_chunk[i] = 1

            # Write encoded chunk bytes (packed)
            # Ensure we write exactly encoded_chunk_byte_len bytes (bitarray.tobytes may pad last byte)
            b = encoded_chunk.tobytes()
            if len(b) < encoded_chunk_byte_len:
                # pad with zeros (shouldn't happen because .tobytes yields ceil(len/8) bytes)
                b = b.ljust(encoded_chunk_byte_len, b'\x00')
            fout.write(b[:encoded_chunk_byte_len])

            # record how many payload bits were stored in this curve
            per_curve_lengths.append(payload_index)
            pointer += payload_index
            curve_index += 1

        # Write per-curve lengths at the end (so decoder can read them)
        lengths_bytes = b''.join(l.to_bytes(4, 'big') for l in per_curve_lengths)
        fout.write(lengths_bytes)

        # Seek back and write header (48 bytes: 16 metadata + 32 SHA256)
        num_curves = len(per_curve_lengths)
        fout.seek(0)
        fout.write(curve_length.to_bytes(4, 'big') +
                   payload_bit_len.to_bytes(4, 'big') +
                   num_curves.to_bytes(4, 'big') +
                   b'\x00\x00\x00\x00')   # reserved
        fout.write(payload_hash)

    # Now zlib-compress the temp file to the final output (streaming read->write)
    compressor = zlib.compressobj(level=9)
    with open(temp_path, "rb") as f_in, open(output_path, "wb") as f_out:
        while True:
            chunk = f_in.read(1 << 20)  # 1MiB chunk
            if not chunk:
                break
            comp = compressor.compress(chunk)
            if comp:
                f_out.write(comp)
        tail = compressor.flush()
        if tail:
            f_out.write(tail)

    remove(temp_path)
    print(f"Encoded (then zlib-compressed) payload written to {output_path}")

# -----------------------------
# Streaming decode (zlib decompress -> regenerate curve -> extract bits -> SHA verify -> lzma decompress)
# -----------------------------
def decode_file_stream(encoded_path: str, seed: bytes, output_path: str):
    # zlib-decompress whole file into memory (you can also stream, but simpler here)
    with open(encoded_path, "rb") as f_in:
        decompressed_bytes = zlib.decompress(f_in.read())

    fin = BytesIO(decompressed_bytes)

    # Read header (48 bytes)
    header = fin.read(48)
    curve_length = int.from_bytes(header[:4], 'big')
    payload_bit_len = int.from_bytes(header[4:8], 'big')
    num_curves = int.from_bytes(header[8:12], 'big')
    # header[12:16] reserved
    payload_hash_stored = header[16:48]  # 32 bytes SHA-256

    # Read per-curve lengths from the end
    fin.seek(-4 * num_curves, 2)
    lengths_bytes = fin.read(4 * num_curves)
    per_curve_lengths = [int.from_bytes(lengths_bytes[i*4:(i+1)*4], 'big') for i in range(num_curves)]

    # Seek back to start of encoded chunks area (right after header)
    fin.seek(48)

    recovered_bits = bitarray()
    encoded_chunk_byte_len = (curve_length + 7) // 8

    for idx, chunk_len in enumerate(per_curve_lengths):
        # Read encoded chunk bytes (curve_length bits packed)
        encoded_bytes = fin.read(encoded_chunk_byte_len)

        chunk_encoded_bits = bitarray()
        chunk_encoded_bits.frombytes(encoded_bytes)
        chunk_encoded_bits = chunk_encoded_bits[:curve_length]

        # Regenerate curve using provided seed and index (fast)
        curve_bits = generate_dh_curve_fast(curve_length, seed, idx)

        # Extract payload bits where the regenerated curve has zeros
        # Stop once we've collected chunk_len bits to avoid over-collecting if curve has >chunk_len zeros
        collected = 0
        for j in range(curve_length):
            if curve_bits[j] == 0:
                recovered_bits.append(chunk_encoded_bits[j])
                collected += 1
                if collected >= chunk_len:
                    break

    # Truncate exactly to payload_bit_len
    recovered_bits = recovered_bits[:payload_bit_len]
    recovered_bytes = recovered_bits.tobytes()

    # Verify SHA-256 of the recovered LZMA-compressed bytes matches stored checksum
    recovered_hash = hashlib.sha256(recovered_bytes).digest()
    if recovered_hash != payload_hash_stored:
        raise ValueError("Checksum mismatch: wrong seed or corrupted data (abort).")

    # LZMA-decompress to original payload
    original_payload = decompress_payload(recovered_bytes)

    with open(output_path, "wb") as fout:
        fout.write(original_payload)

    print(f"Recovered payload written to {output_path}")

# -----------------------------
# CLI
# -----------------------------
if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage:")
        print("  Encode: python DH.py encode <seed> <input_file> <output_encoded_file>")
        print("  Decode: python DH.py decode <seed> <encoded_file> <output_file>")
        sys.exit(1)

    mode = sys.argv[1]
    seed_input = sys.argv[2].encode()

    if mode == "encode":
        input_file = sys.argv[3]
        output_file = sys.argv[4]

        # auto-select curve length
        file_size = getsize(input_file)
        curve_length = auto_curve_length(file_size)
        print(f"[info] Auto-selected curve length = {curve_length} bits for {file_size} bytes input")

        encode_file_stream(input_file, seed_input, curve_length, output_file)

    elif mode == "decode":
        try:
            decode_file_stream(sys.argv[3], seed_input, sys.argv[4])
        except Exception as e:
            print("Decode failed:", e)
            sys.exit(2)
    else:
        print("Invalid mode. Use 'encode' or 'decode'.")
        sys.exit(1)