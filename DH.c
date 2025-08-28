// DH.c
// sudo apt-get install liblzma-dev zlib1g-dev libssl-dev
// Build: gcc -O3 -std=c11 DH.c -o DH -llzma -lz -lcrypto

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#include <openssl/sha.h>
#include <zlib.h>
#include <lzma.h>

// -----------------------------
// Helpers: bit operations
// -----------------------------
static inline void set_bit(uint8_t *buf, size_t bit_index, int v) {
    size_t byte_idx = bit_index >> 3;
    int bit_in_byte = bit_index & 7;
    if (v)
        buf[byte_idx] |= (1u << bit_in_byte);
    else
        buf[byte_idx] &= ~(1u << bit_in_byte);
}

static inline int get_bit(const uint8_t *buf, size_t bit_index) {
    size_t byte_idx = bit_index >> 3;
    int bit_in_byte = bit_index & 7;
    return (buf[byte_idx] >> bit_in_byte) & 1u;
}

// -----------------------------
// Auto curve length
// -----------------------------
size_t auto_curve_length(size_t file_size) {
    if (file_size < (1ULL << 20)) return 512;
    else if (file_size < (50ULL << 20)) return 4096;
    else if (file_size < (500ULL << 20)) return 8192;
    else return 16384;
}

// -----------------------------
// Fast curve generation using SHA256
// -----------------------------
int generate_curve_fast(uint8_t *curve_bits, size_t curve_len_bits,
                        const uint8_t *seed, size_t seed_len, uint32_t idx) {
    size_t bytes_needed = (curve_len_bits + 7) >> 3;
    memset(curve_bits, 0, bytes_needed);

    uint32_t counter = 0;
    size_t bits_filled = 0;
    while (bits_filled < curve_len_bits) {
        uint8_t inbuf[seed_len + 8];
        memcpy(inbuf, seed, seed_len);
        inbuf[seed_len + 0] = (idx >> 24) & 0xFF;
        inbuf[seed_len + 1] = (idx >> 16) & 0xFF;
        inbuf[seed_len + 2] = (idx >> 8) & 0xFF;
        inbuf[seed_len + 3] = (idx) & 0xFF;
        inbuf[seed_len + 4] = (counter >> 24) & 0xFF;
        inbuf[seed_len + 5] = (counter >> 16) & 0xFF;
        inbuf[seed_len + 6] = (counter >> 8) & 0xFF;
        inbuf[seed_len + 7] = (counter) & 0xFF;

        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256(inbuf, seed_len + 8, digest);

        for (size_t b = 0; b < SHA256_DIGEST_LENGTH * 8 && bits_filled < curve_len_bits; ++b) {
            size_t byte_of_digest = b >> 3;
            int bit_in_digest = b & 7;
            int bit = (digest[byte_of_digest] >> bit_in_digest) & 1u;
            set_bit(curve_bits, bits_filled, bit);
            bits_filled++;
        }
        counter++;
    }
    return 0;
}

// -----------------------------
// LZMA helpers
// -----------------------------
int lzma_compress_buffer(const uint8_t *in, size_t in_size, uint8_t **out, size_t *out_size) {
    size_t estimate = in_size + (in_size >> 4) + 65536;
    *out = malloc(estimate);
    if (!*out) return -1;
    lzma_ret ret = lzma_easy_buffer_encode(LZMA_PRESET_DEFAULT | LZMA_PRESET_EXTREME,
                                           LZMA_CHECK_CRC64, NULL,
                                           in, in_size, *out, out_size, estimate);
    if (ret != LZMA_OK) { free(*out); *out = NULL; return -2; }
    return 0;
}

int lzma_decompress_buffer_simple(const uint8_t *in, size_t in_size, uint8_t **out, size_t *out_size) {
    uint64_t memlimit = UINT64_MAX;
    size_t in_pos = 0, out_pos = 0;
    size_t out_cap = in_size * 4 + 1024;
    *out = malloc(out_cap);
    if (!*out) return -1;
    lzma_ret ret = lzma_stream_buffer_decode(&memlimit, 0, NULL,
                                             in, &in_pos, in_size,
                                             *out, &out_pos, out_cap);
    if (ret != LZMA_OK) { free(*out); *out = NULL; return -2; }
    *out_size = out_pos;
    return 0;
}

// -----------------------------
// zlib compress file streaming
// -----------------------------
int zlib_compress_file_stream(const char *temp_path, const char *out_path) {
    FILE *f_in = fopen(temp_path, "rb");
    if (!f_in) { perror("fopen temp"); return -1; }
    FILE *f_out = fopen(out_path, "wb");
    if (!f_out) { perror("fopen out"); fclose(f_in); return -1; }

    int ret = 0;
    z_stream zs; memset(&zs,0,sizeof(zs));
    if (deflateInit(&zs,Z_BEST_COMPRESSION)!=Z_OK){ret=-2;goto cleanup;}

    const size_t BUFSZ=1<<20;
    uint8_t *inbuf = malloc(BUFSZ);
    uint8_t *outbuf = malloc(BUFSZ);
    if(!inbuf||!outbuf){ret=-3;goto cleanup_deflate;}

    while(1){
        size_t n=fread(inbuf,1,BUFSZ,f_in);
        zs.next_in=inbuf; zs.avail_in=(uInt)n;
        int flush=feof(f_in)?Z_FINISH:Z_NO_FLUSH;
        do{
            zs.next_out=outbuf; zs.avail_out=BUFSZ;
            int zret=deflate(&zs,flush);
            if(zret==Z_STREAM_ERROR){ret=-4;goto cleanup_buffers;}
            size_t have=BUFSZ-zs.avail_out;
            if(have) if(fwrite(outbuf,1,have,f_out)!=have){ret=-5;goto cleanup_buffers;}
        }while(zs.avail_out==0);
        if(flush==Z_FINISH) break;
    }

cleanup_buffers: free(inbuf); free(outbuf); deflateEnd(&zs);
cleanup_deflate:;
cleanup: fclose(f_in); fclose(f_out);
    return ret;
}

// -----------------------------
// encode/decode implementations
// -----------------------------
int write_u32_be(FILE *f,uint32_t v){uint8_t b[4]={v>>24,v>>16,v>>8,v};return fwrite(b,1,4,f)==4?0:-1;}
uint32_t read_u32_be(const uint8_t *b){return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|((uint32_t)b[3]);}

int encode_file_stream(const char *input_path, const uint8_t *seed, size_t seed_len,
                       size_t curve_length_bits, const char *output_path) {
    // read input file entirely
    FILE *fin = fopen(input_path, "rb");
    if (!fin) { perror("fopen input"); return -1; }
    struct stat st; if (fstat(fileno(fin), &st) != 0) { perror("fstat"); fclose(fin); return -1; }
    size_t in_size = st.st_size;
    uint8_t *inbuf = malloc(in_size);
    if (!inbuf) { fclose(fin); return -1; }
    if (fread(inbuf, 1, in_size, fin) != in_size) { perror("fread"); free(inbuf); fclose(fin); return -1; }
    fclose(fin);

    // LZMA compress
    uint8_t *lzma_buf = NULL; size_t lzma_size = 0;
    if (lzma_compress_buffer(inbuf, in_size, &lzma_buf, &lzma_size) != 0) {
        fprintf(stderr, "LZMA compression failed\n");
        free(inbuf); return -1;
    }
    free(inbuf);

    // SHA256 of compressed payload
    uint8_t payload_hash[SHA256_DIGEST_LENGTH];
    SHA256(lzma_buf, lzma_size, payload_hash);

    // prepare payload bits
    size_t payload_bits_len = lzma_size * 8;
    uint8_t *payload_bits = lzma_buf; // we will read bits from lzma_buf directly (packed bytes)

    // temp file path
    char temp_path[4096];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", output_path);

    FILE *fout = fopen(temp_path, "wb");
    if (!fout) { perror("fopen temp"); free(lzma_buf); return -1; }

    // header placeholder (48 bytes)
    uint8_t header_placeholder[48] = {0};
    if (fwrite(header_placeholder, 1, 48, fout) != 48) { perror("fwrite header"); fclose(fout); free(lzma_buf); return -1; }

    // iterate curves
    size_t pointer = 0; // bits consumed
    uint32_t curve_index = 0;
    uint32_t *per_curve_lengths = NULL;
    size_t per_curve_count = 0;
    size_t per_curve_capacity = 0;

    size_t encoded_chunk_bytes = (curve_length_bits + 7) >> 3;
    uint8_t *curve_bits = malloc((curve_length_bits + 7) >> 3);
    uint8_t *encoded_chunk = malloc(encoded_chunk_bytes);
    if (!curve_bits || !encoded_chunk) { perror("malloc"); fclose(fout); free(lzma_buf); free(curve_bits); free(encoded_chunk); return -1; }

    while (pointer < payload_bits_len) {
        // grow per_curve_lengths
        if (per_curve_count + 1 > per_curve_capacity) {
            size_t newcap = per_curve_capacity == 0 ? 1024 : per_curve_capacity * 2;
            uint32_t *tmp = realloc(per_curve_lengths, newcap * sizeof(uint32_t));
            if (!tmp) { perror("realloc"); fclose(fout); free(lzma_buf); free(curve_bits); free(encoded_chunk); free(per_curve_lengths); return -1; }
            per_curve_lengths = tmp;
            per_curve_capacity = newcap;
        }

        generate_curve_fast(curve_bits, curve_length_bits, seed, seed_len, curve_index);

        // count zeros: we'll use to know how many payload bits we can take; but we inject inline
        // produce encoded_chunk
        memset(encoded_chunk, 0, encoded_chunk_bytes);
        uint32_t consumed_in_curve = 0;
        for (size_t bitpos = 0; bitpos < curve_length_bits; ++bitpos) {
            int cbit = get_bit(curve_bits, bitpos);
            if (cbit == 0) {
                // take next payload bit if available
                if (pointer < payload_bits_len) {
                    int pv = get_bit(payload_bits, pointer);
                    set_bit(encoded_chunk, bitpos, pv);
                    pointer++;
                    consumed_in_curve++;
                } else {
                    set_bit(encoded_chunk, bitpos, 0);
                }
            } else {
                // curve had 1 -> set encoded bit to 1
                set_bit(encoded_chunk, bitpos, 1);
            }
        }

        // write encoded_chunk bytes
        if (fwrite(encoded_chunk, 1, encoded_chunk_bytes, fout) != encoded_chunk_bytes) {
            perror("fwrite encoded chunk");
            fclose(fout); free(lzma_buf); free(curve_bits); free(encoded_chunk); free(per_curve_lengths); return -1;
        }

        // store length
        per_curve_lengths[per_curve_count++] = consumed_in_curve;
        curve_index++;
    }

    // write per-curve lengths
    for (size_t i = 0; i < per_curve_count; ++i) {
        uint32_t v = per_curve_lengths[i];
        uint8_t b[4];
        b[0] = (v >> 24) & 0xFF;
        b[1] = (v >> 16) & 0xFF;
        b[2] = (v >> 8) & 0xFF;
        b[3] = (v) & 0xFF;
        if (fwrite(b, 1, 4, fout) != 4) { perror("fwrite lengths"); fclose(fout); free(lzma_buf); free(curve_bits); free(encoded_chunk); free(per_curve_lengths); return -1; }
    }

    // write header now
    // 4B curve_length, 4B payload_bit_len, 4B num_curves, 4B reserved, then 32B sha256
    if (fseek(fout, 0, SEEK_SET) != 0) { perror("fseek"); fclose(fout); free(lzma_buf); free(curve_bits); free(encoded_chunk); free(per_curve_lengths); return -1; }
    uint8_t head[48];
    memset(head, 0, 48);
    head[0] = (uint8_t)((curve_length_bits >> 24) & 0xFF);
    head[1] = (uint8_t)((curve_length_bits >> 16) & 0xFF);
    head[2] = (uint8_t)((curve_length_bits >> 8) & 0xFF);
    head[3] = (uint8_t)((curve_length_bits) & 0xFF);
    head[4] = (uint8_t)((payload_bits_len >> 24) & 0xFF);
    head[5] = (uint8_t)((payload_bits_len >> 16) & 0xFF);
    head[6] = (uint8_t)((payload_bits_len >> 8) & 0xFF);
    head[7] = (uint8_t)((payload_bits_len) & 0xFF);
    head[8]  = (uint8_t)((per_curve_count >> 24) & 0xFF);
    head[9]  = (uint8_t)((per_curve_count >> 16) & 0xFF);
    head[10] = (uint8_t)((per_curve_count >> 8) & 0xFF);
    head[11] = (uint8_t)((per_curve_count) & 0xFF);
    // head[12..15] reserved zero
    memcpy(head + 16, payload_hash, SHA256_DIGEST_LENGTH);
    if (fwrite(head, 1, 48, fout) != 48) { perror("fwrite header"); fclose(fout); free(lzma_buf); free(curve_bits); free(encoded_chunk); free(per_curve_lengths); return -1; }

    fclose(fout);

    // zlib-compress temp file -> final output
    if (zlib_compress_file_stream(temp_path, output_path) != 0) {
        fprintf(stderr, "zlib compression failed\n");
        free(lzma_buf); free(curve_bits); free(encoded_chunk); free(per_curve_lengths);
        remove(temp_path);
        return -1;
    }

    // cleanup
    remove(temp_path);
    free(lzma_buf); free(curve_bits); free(encoded_chunk); free(per_curve_lengths);

    printf("Encoded (then zlib-compressed) payload written to %s\n", output_path);
    return 0;
}

int decode_file_stream(const char *encoded_path, const uint8_t *seed, size_t seed_len, const char *output_path) {
    // read entire encoded file
    FILE *fenc = fopen(encoded_path, "rb");
    if (!fenc) { perror("fopen encoded"); return -1; }
    struct stat st; if (fstat(fileno(fenc), &st) != 0) { perror("fstat"); fclose(fenc); return -1; }
    size_t enc_size = st.st_size;
    uint8_t *enc_buf = malloc(enc_size);
    if (!enc_buf) { fclose(fenc); return -1; }
    if (fread(enc_buf, 1, enc_size, fenc) != enc_size) { perror("fread"); free(enc_buf); fclose(fenc); return -1; }
    fclose(fenc);

    // zlib decompress entire buffer (use uncompress with estimation; input might be smaller)
    // Use zlib uncompress with growing buffer
    uLongf est = enc_size * 4 + 1024;
    uint8_t *decomp = malloc(est);
    int zret;
    while ((zret = uncompress(decomp, &est, enc_buf, enc_size)) == Z_BUF_ERROR) {
        // enlarge
        est *= 2;
        uint8_t *tmp = realloc(decomp, est);
        if (!tmp) { free(enc_buf); free(decomp); return -1; }
        decomp = tmp;
    }
    if (zret != Z_OK) { fprintf(stderr, "zlib uncompress failed: %d\n", zret); free(enc_buf); free(decomp); return -1; }

    size_t decomp_size = est;
    free(enc_buf);

    // parse header (48 bytes)
    if (decomp_size < 48) { fprintf(stderr, "decompressed too small\n"); free(decomp); return -1; }
    uint8_t *p = decomp;
    size_t curve_length_bits = ((size_t)p[0] << 24) | ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | (size_t)p[3];
    size_t payload_bits_len = ((size_t)p[4] << 24) | ((size_t)p[5] << 16) | ((size_t)p[6] << 8) | (size_t)p[7];
    size_t num_curves = ((size_t)p[8] << 24) | ((size_t)p[9] << 16) | ((size_t)p[10] << 8) | (size_t)p[11];
    uint8_t payload_hash_stored[SHA256_DIGEST_LENGTH];
    memcpy(payload_hash_stored, p + 16, SHA256_DIGEST_LENGTH);

    // find per-curve lengths at the end
    if (decomp_size < 48 + ((curve_length_bits + 7) >> 3) * num_curves + 4 * num_curves) {
        // not a strict check but continue
    }
    // pointer to lengths: last 4*num_curves bytes
    uint8_t *lengths_ptr = decomp + decomp_size - (4 * num_curves);
    uint32_t *per_curve_lengths = malloc(sizeof(uint32_t) * num_curves);
    for (size_t i = 0; i < num_curves; ++i) {
        per_curve_lengths[i] = read_u32_be(lengths_ptr + i * 4);
    }

    // pointer to first encoded chunk
    uint8_t *encoded_ptr = decomp + 48;
    size_t encoded_chunk_bytes = (curve_length_bits + 7) >> 3;

    uint8_t *curve_bits = malloc(encoded_chunk_bytes);
    if (!curve_bits) { fprintf(stderr, "malloc failed\n"); free(decomp); free(per_curve_lengths); return -1; }

    // recovered bits buffer: payload_bits_len bits => bytes needed
    size_t recovered_bytes_needed = (payload_bits_len + 7) >> 3;
    uint8_t *recovered = malloc(recovered_bytes_needed);
    if (!recovered) { free(decomp); free(per_curve_lengths); free(curve_bits); return -1; }
    memset(recovered, 0, recovered_bytes_needed);
    size_t recovered_bit_pos = 0;

    // iterate curves and extract according to regenerated curves
    uint8_t *enc_cursor = encoded_ptr;
    for (size_t idx = 0; idx < num_curves; ++idx) {
        // read encoded chunk bytes
        uint8_t *enc_chunk = enc_cursor;
        enc_cursor += encoded_chunk_bytes;

        // regen curve
        generate_curve_fast(curve_bits, curve_length_bits, seed, seed_len, (uint32_t)idx);

        uint32_t want_bits = per_curve_lengths[idx];
        uint32_t collected = 0;
        for (size_t j = 0; j < curve_length_bits && collected < want_bits; ++j) {
            if (get_bit(curve_bits, j) == 0) {
                // this position carries payload bit
                int bit = get_bit(enc_chunk, j);
                set_bit(recovered, recovered_bit_pos, bit);
                recovered_bit_pos++;
                collected++;
                if (recovered_bit_pos >= payload_bits_len) break;
            }
        }
    }

    // truncate to payload_bits_len (already done by not writing more)
    // convert recovered bits buffer to bytes (already packed)

    // compute sha256 of recovered bytes (these should be LZMA-compressed payload)
    size_t recovered_bytes_len = (payload_bits_len + 7) >> 3;
    uint8_t recovered_hash[SHA256_DIGEST_LENGTH];
    SHA256(recovered, recovered_bytes_len, recovered_hash);
    if (memcmp(recovered_hash, payload_hash_stored, SHA256_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "Checksum mismatch: wrong seed or corrupted data (abort).\n");
        free(decomp); free(per_curve_lengths); free(curve_bits); free(recovered);
        return -1;
    }

    // LZMA-decompress recovered (use lzma_stream_buffer_decode)
    uint8_t *orig = NULL; size_t orig_size = 0;
    if (lzma_decompress_buffer_simple(recovered, recovered_bytes_len, &orig, &orig_size) != 0) {
        fprintf(stderr, "LZMA decompression of recovered payload failed\n");
        free(decomp); free(per_curve_lengths); free(curve_bits); free(recovered);
        return -1;
    }

    // write to output_path
    FILE *fout = fopen(output_path, "wb");
    if (!fout) { perror("fopen out"); free(decomp); free(per_curve_lengths); free(curve_bits); free(recovered); free(orig); return -1; }
    if (fwrite(orig, 1, orig_size, fout) != orig_size) { perror("fwrite out"); fclose(fout); free(decomp); free(per_curve_lengths); free(curve_bits); free(recovered); free(orig); return -1; }
    fclose(fout);

    printf("Recovered payload written to %s\n", output_path);

    // cleanup
    free(decomp);
    free(per_curve_lengths);
    free(curve_bits);
    free(recovered);
    free(orig);

    return 0;
}



// -----------------------------
// CLI
// -----------------------------
void usage(const char *prog) {
    fprintf(stderr,"Usage:\n  %s encode <seed> <input_file> <output_file>\n  %s decode <seed> <input_file> <output_file>\n",prog,prog);
}

int main(int argc,char **argv){
    if(argc<5){usage(argv[0]);return 1;}
    const char *mode=argv[1]; const char *seed_str=argv[2];
    const char *in_path=argv[3]; const char *out_path=argv[4];
    size_t seed_len=strlen(seed_str);
    const uint8_t *seed=(const uint8_t*)seed_str;

    if(strcmp(mode,"encode")==0){
        struct stat st; if(stat(in_path,&st)!=0){perror("stat");return 1;}
        size_t curve_length=auto_curve_length(st.st_size);
        fprintf(stderr,"[info] Auto-selected curve length = %zu bits\n",curve_length);
        if(encode_file_stream(in_path,seed,seed_len,curve_length,out_path)!=0){fprintf(stderr,"encode failed\n");return 1;}
    } else if(strcmp(mode,"decode")==0){
        if(decode_file_stream(in_path,seed,seed_len,out_path)!=0){fprintf(stderr,"decode failed\n");return 1;}
    } else {usage(argv[0]);return 1;}
    return 0;
}
