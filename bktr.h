#ifndef HACPACK_NCA_COMPRESS_H
#define HACPACK_NCA_COMPRESS_H

#include "types.h"
#include "filepath.h"
#include "nca.h"

/* BucketTree (BKTR) constants. */
#define MAGIC_BKTR 0x52544B42 /* "BKTR" */
#define BKTR_NODE_SIZE 0x4000

/* Number of bytes of an IVFC level that is compressed into a single entry. */
#define NCA_COMPRESS_BLOCK_SIZE 0x4000

/* BucketTree node header (0x10 bytes). */
#pragma pack(push, 1)
typedef struct
{
    int32_t index;
    int32_t entry_count;
    int64_t offset_end;
} bktr_node_header_t;
#pragma pack(pop)

/* CompressedStorage entry, size 0x18 (natural alignment). Bytes 0x11..0x13 are reserved. */
typedef struct
{
    uint64_t virtual_offset;
    uint64_t physical_offset;
    uint8_t compression_type;
    uint8_t reserved[3];
    uint32_t physical_size;
} nca_compress_entry_t;

enum nca_compress_type
{
    COMPRESS_TYPE_NONE = 0,
    COMPRESS_TYPE_ZEROED = 1,
    COMPRESS_TYPE_LZ4 = 3
};

/* A built compression layer, ready to be written for a RomFS section. */
typedef struct
{
    uint8_t *bktr_header;   /* Serialized BKTR table header (0x10 bytes). */
    uint8_t *nodes;         /* Node storage (L1/L2 index nodes). */
    uint64_t nodes_size;
    uint8_t *entry_sets;    /* Entry-set storage. */
    uint64_t entry_sets_size;
    uint64_t table_size;    /* Total size of the node + entry-set storage. */
    uint64_t entry_data_size; /* Size of the compressed entry-data region. */
    uint64_t table_offset;  /* Node storage offset (= entry_data_size). */
    uint64_t virtual_size;  /* Uncompressed RomFS size. */
} nca_compress_result_t;

/* Compresses `data_size` bytes of raw RomFS payload (IVFC level 6) from `src`
 * into a BKTR compression layer. Returns 0 on success, -1 on failure. */
int nca_compress_build(FILE *src, uint64_t data_size, int level, filepath_t *temp_dir, nca_compress_result_t *out);

void nca_compress_result_free(nca_compress_result_t *result);

/* Writes a built compression layer (`[entry data][nodes][entry sets]`) to
 * `nca_file` and fills in the section FS header CompressionInfo. */
void nca_compress_write(nca_compress_result_t *result, FILE *nca_file, filepath_t *temp_dir, nca_fs_header_t *fs_header, uint64_t table_offset, uint64_t entry_data_size);

#endif
