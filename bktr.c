#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bktr.h"
#include "utils.h"

#include "lz4.h"

/* Temporary file holding the compressed entry data. */
#define COMPRESS_ENTRY_TEMP_NAME "compress_entries"

/* Number of entries that fit in an entry-set node. */
static int compress_entry_count_per_node(uint64_t node_size, uint64_t entry_size)
{
    return (int)((node_size - sizeof(bktr_node_header_t)) / entry_size);
}

/* Number of offsets that fit in an index node. */
static int compress_offset_count_per_node(uint64_t node_size)
{
    return (int)((node_size - sizeof(bktr_node_header_t)) / sizeof(int64_t));
}

void nca_compress_result_free(nca_compress_result_t *result)
{
    if (result == NULL)
        return;
    free(result->bktr_header);
    free(result->nodes);
    free(result->entry_sets);
    memset(result, 0, sizeof(*result));
}

/* Reads `count` bytes at `offset` within the input file into `buffer`. */
static int compress_read_at(FILE *f, uint64_t offset, void *buffer, size_t count)
{
    if (fseeko64(f, (int64_t)offset, SEEK_SET) != 0)
        return -1;
    return fread(buffer, 1, count, f) == count ? 0 : -1;
}

/* Returns the compressed size, or 0 if the data is not compressible. */
static uint32_t compress_block(const uint8_t *data, size_t size, uint8_t compression_type, int level, uint8_t *dst, size_t dst_capacity)
{
    if (size == 0 || compression_type != COMPRESS_TYPE_LZ4)
        return 0;

    (void)level;
    if (size > (size_t)INT32_MAX || dst_capacity > (size_t)INT32_MAX)
        return 0;

    int result = LZ4_compress_default((const char *)data, (char *)dst, (int)size, (int)dst_capacity);
    if (result <= 0 || (size_t)result >= size)
        return 0;
    return (uint32_t)result;
}

/* Returns 1 if the `size` bytes in `data` are all zero. */
static int block_is_zero(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        if (data[i] != 0)
            return 0;
    }
    return 1;
}

int nca_compress_build(FILE *src, uint64_t data_size, int level, filepath_t *temp_dir, nca_compress_result_t *out)
{
    memset(out, 0, sizeof(*out));

    if (data_size == 0)
        return -1;

    /* NCA compression only supports LZ4 (compression_type 3). Levels 1-3 map to
     * LZ4 for CLI compatibility; the level is otherwise unused. */
    uint8_t compression_type = COMPRESS_TYPE_LZ4;
    int compression_level = level < 1 ? 1 : (level > 3 ? 3 : level);

    uint64_t entry_count = (data_size + NCA_COMPRESS_BLOCK_SIZE - 1) / NCA_COMPRESS_BLOCK_SIZE;
    if (entry_count == 0 || entry_count > (uint64_t)INT32_MAX)
        return -1;

    int entry_count_per_node = compress_entry_count_per_node(BKTR_NODE_SIZE, sizeof(nca_compress_entry_t));
    int offset_count_per_node = compress_offset_count_per_node(BKTR_NODE_SIZE);
    int entry_set_count = (int)((entry_count + entry_count_per_node - 1) / entry_count_per_node);

    /* An L2 index level is needed when the entry-set offsets do not all fit in
     * the single L1 node. */
    int node_l2_count = 0;
    if (entry_set_count > offset_count_per_node)
    {
        int n = (entry_set_count + offset_count_per_node - 1) / offset_count_per_node;
        node_l2_count = (entry_set_count - (offset_count_per_node - (n - 1)) + offset_count_per_node - 1) / offset_count_per_node;

        /* The L2 directory occupies the first `node_l2_count` L1 offsets, so it
         * must fit. Only absurdly large sections can violate this. */
        if (node_l2_count > offset_count_per_node)
            return -1;
    }

    /* Entry-set start offsets stored directly in L1, after the L2 directory. */
    int offsets_in_l1;
    if (node_l2_count == 0)
        offsets_in_l1 = entry_set_count;
    else
        offsets_in_l1 = offset_count_per_node - node_l2_count;

    uint64_t nodes_size = (uint64_t)(1 + node_l2_count) * BKTR_NODE_SIZE;
    uint64_t entry_sets_size = (uint64_t)entry_set_count * BKTR_NODE_SIZE;
    uint64_t table_size = nodes_size + entry_sets_size;

    uint8_t *nodes = (uint8_t *)calloc(1, (size_t)nodes_size);
    uint8_t *entry_sets = (uint8_t *)calloc(1, (size_t)entry_sets_size);

    filepath_t entry_filepath;
    filepath_init(&entry_filepath);
    filepath_copy(&entry_filepath, temp_dir);
    filepath_append(&entry_filepath, COMPRESS_ENTRY_TEMP_NAME);
    FILE *entry_file = os_fopen(entry_filepath.os_path, OS_MODE_WRITE_EDIT);

    if (nodes == NULL || entry_sets == NULL || entry_file == NULL)
    {
        fprintf(stderr, "Error: Failed to allocate NCA compression buffers!\n");
        free(nodes);
        free(entry_sets);
        if (entry_file != NULL)
            fclose(entry_file);
        return -1;
    }

    /* Physical offset and size of every entry, in order (the size is explicit
     * because 0x10-byte alignment padding may separate entries). */
    uint64_t *physical_offsets = (uint64_t *)malloc(sizeof(uint64_t) * (size_t)entry_count);
    uint32_t *physical_sizes = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)entry_count);
    uint8_t *data = (uint8_t *)malloc(NCA_COMPRESS_BLOCK_SIZE);
    size_t comp_capacity = (size_t)LZ4_compressBound((int)NCA_COMPRESS_BLOCK_SIZE);
    uint8_t *compressed = (uint8_t *)malloc(comp_capacity);

    if (physical_offsets == NULL || physical_sizes == NULL || data == NULL || compressed == NULL)
    {
        fprintf(stderr, "Error: Failed to allocate NCA compression buffers!\n");
        free(physical_offsets);
        free(physical_sizes);
        free(data);
        free(compressed);
        free(nodes);
        free(entry_sets);
        fclose(entry_file);
        return -1;
    }

    uint64_t physical_offset = 0;
    int ok = 1;

    for (uint64_t i = 0; i < entry_count; i++)
    {
        uint64_t block_offset = i * NCA_COMPRESS_BLOCK_SIZE;
        size_t block_size = (size_t)((data_size - block_offset > NCA_COMPRESS_BLOCK_SIZE) ? NCA_COMPRESS_BLOCK_SIZE : (data_size - block_offset));

        if (compress_read_at(src, block_offset, data, block_size) != 0)
        {
            fprintf(stderr, "Error: Failed to read source data for NCA compression!\n");
            ok = 0;
            break;
        }

        physical_offsets[i] = physical_offset;

        uint32_t compressed_size = compress_block(data, block_size, compression_type, compression_level, compressed, comp_capacity);
        if (block_is_zero(data, block_size))
        {
            /* Fully-zeroed block: store no physical data (ZEROED). */
            physical_sizes[i] = 0;
        }
        else if (compressed_size != 0)
        {
            if (fwrite(compressed, 1, compressed_size, entry_file) != compressed_size)
            {
                fprintf(stderr, "Error: Failed to write compressed entry!\n");
                ok = 0;
                break;
            }
            physical_sizes[i] = compressed_size;
            physical_offset += compressed_size;

            /* LZ4 entries must start 0x10-aligned; the padding is written here
             * (between entries) and is not part of the entry's data size. */
            uint64_t aligned_offset = (physical_offset + 0xF) & ~(uint64_t)0xF;
            if (aligned_offset != physical_offset)
            {
                uint64_t pad = aligned_offset - physical_offset;
                unsigned char zeropad[0x10] = {0};
                if (fwrite(zeropad, 1, (size_t)pad, entry_file) != pad)
                {
                    fprintf(stderr, "Error: Failed to write entry alignment padding!\n");
                    ok = 0;
                    break;
                }
                physical_offset = aligned_offset;
            }
        }
        else
        {
            if (fwrite(data, 1, block_size, entry_file) != block_size)
            {
                fprintf(stderr, "Error: Failed to write uncompressed entry!\n");
                ok = 0;
                break;
            }
            physical_sizes[i] = (uint32_t)block_size;
            physical_offset += block_size;
        }
    }

    if (ok)
    {
        /* Build the entry sets. */
        for (int set_index = 0; set_index < entry_set_count; set_index++)
        {
            uint8_t *node = entry_sets + (uint64_t)set_index * BKTR_NODE_SIZE;
            bktr_node_header_t *header = (bktr_node_header_t *)node;
            nca_compress_entry_t *entries = (nca_compress_entry_t *)(node + sizeof(bktr_node_header_t));

            uint64_t base_entry = (uint64_t)set_index * entry_count_per_node;
            uint64_t set_entry_count = entry_count - base_entry;
            if (set_entry_count > (uint64_t)entry_count_per_node)
                set_entry_count = entry_count_per_node;

            header->index = set_index;
            header->entry_count = (int32_t)set_entry_count;
            header->offset_end = (int64_t)((base_entry + set_entry_count) * NCA_COMPRESS_BLOCK_SIZE);
            if (header->offset_end > (int64_t)data_size)
                header->offset_end = (int64_t)data_size;

            for (uint64_t j = 0; j < set_entry_count; j++)
            {
                uint64_t entry_index = base_entry + j;
                uint64_t voff = entry_index * NCA_COMPRESS_BLOCK_SIZE;
                uint64_t vlen = (entry_index + 1 < entry_count) ? NCA_COMPRESS_BLOCK_SIZE : (data_size - voff);
                uint32_t phys_size = physical_sizes[entry_index];

                entries[j].virtual_offset = voff;
                /* Physical offsets are relative to the section data start. */
                entries[j].physical_offset = physical_offsets[entry_index];
                entries[j].reserved[0] = 0;
                entries[j].reserved[1] = 0;
                entries[j].reserved[2] = 0;
                if (phys_size == 0)
                {
                    entries[j].compression_type = COMPRESS_TYPE_ZEROED;
                    entries[j].physical_size = 0;
                }
                else if (phys_size == vlen)
                {
                    /* Stored verbatim (also covers the final partial block). */
                    entries[j].compression_type = COMPRESS_TYPE_NONE;
                    entries[j].physical_size = (uint32_t)vlen;
                }
                else
                {
                    entries[j].compression_type = compression_type;
                    entries[j].physical_size = phys_size;
                }
            }
        }

        /* Build the L1 index node, and the separately-stored L2 nodes. */
        uint8_t *l1 = nodes;
        bktr_node_header_t *l1_header = (bktr_node_header_t *)l1;
        uint64_t *l1_offsets = (uint64_t *)(l1 + sizeof(bktr_node_header_t));
        l1_header->index = 0;
        l1_header->offset_end = (int64_t)data_size;

        if (node_l2_count == 0)
        {
            /* Without an L2 level, L1 holds the start virtual offset of every
             * entry set (the reader binary-searches it directly). */
            l1_header->entry_count = entry_set_count;
            for (int i = 0; i < entry_set_count; i++)
            {
                bktr_node_header_t *header = (bktr_node_header_t *)(entry_sets + (uint64_t)i * BKTR_NODE_SIZE);
                l1_offsets[i] = (uint64_t)header->index * (uint64_t)entry_count_per_node * NCA_COMPRESS_BLOCK_SIZE;
            }
        }
        else
        {
            /* With an L2 level, L1[0..node_l2_count) holds the start virtual
             * offset of each L2 node and L1[node_l2_count..) the start offsets
             * of the first `offsets_in_l1` entry sets. L2 node #k (storage
             * index k) covers entry sets starting at that layout's boundary. */
            int l2_first_set = offset_count_per_node - node_l2_count;

            l1_header->entry_count = node_l2_count;

            uint64_t *tail = l1_offsets + node_l2_count;
            for (int i = 0; i < offsets_in_l1; i++)
            {
                bktr_node_header_t *header = (bktr_node_header_t *)(entry_sets + (uint64_t)i * BKTR_NODE_SIZE);
                tail[i] = (uint64_t)header->index * (uint64_t)entry_count_per_node * NCA_COMPRESS_BLOCK_SIZE;
            }

            for (int i = 0; i < node_l2_count; i++)
            {
                uint8_t *node = nodes + (uint64_t)(i + 1) * BKTR_NODE_SIZE;
                bktr_node_header_t *header = (bktr_node_header_t *)node;
                uint64_t *l2_offsets = (uint64_t *)(node + sizeof(bktr_node_header_t));

                int first_set = l2_first_set + i * offset_count_per_node;
                int set_count = entry_set_count - first_set;
                if (set_count > offset_count_per_node)
                    set_count = offset_count_per_node;

                header->index = i;
                header->entry_count = set_count;
                header->offset_end = (int64_t)(first_set + set_count) * (int64_t)NCA_COMPRESS_BLOCK_SIZE;
                if (header->offset_end > (int64_t)data_size)
                    header->offset_end = (int64_t)data_size;

                bktr_node_header_t *first = (bktr_node_header_t *)(entry_sets + (uint64_t)first_set * BKTR_NODE_SIZE);
                l1_offsets[i] = (uint64_t)first->index * (uint64_t)entry_count_per_node * NCA_COMPRESS_BLOCK_SIZE;

                for (int j = 0; j < set_count; j++)
                {
                    bktr_node_header_t *set_header = (bktr_node_header_t *)(entry_sets + (uint64_t)(first_set + j) * BKTR_NODE_SIZE);
                    l2_offsets[j] = (uint64_t)set_header->index * (uint64_t)entry_count_per_node * NCA_COMPRESS_BLOCK_SIZE;
                }
            }
        }

        /* Serialize the 0x10-byte BucketTreeHeader (magic, version,
         * entry_count, reserved) stored inline in the FS header at 0x188. */
        uint8_t *bktr_header = (uint8_t *)calloc(1, 0x10);
        if (bktr_header == NULL)
        {
            ok = 0;
        }
        else
        {
            uint32_t magic = MAGIC_BKTR;
            uint32_t version = 1; /* BucketTree version. */
            uint32_t reserved = 0;
            uint32_t num_entries = (uint32_t)entry_count;

            memcpy(bktr_header + 0x00, &magic, 4);
            memcpy(bktr_header + 0x04, &version, 4);
            memcpy(bktr_header + 0x08, &num_entries, 4);
            memcpy(bktr_header + 0x0C, &reserved, 4);

            out->bktr_header = bktr_header;
            out->nodes = nodes;
            out->nodes_size = nodes_size;
            out->entry_sets = entry_sets;
            out->entry_sets_size = entry_sets_size;
            out->table_size = table_size;
            /* Entry data is written first, so the node storage begins here. */
            out->entry_data_size = physical_offset;
            out->table_offset = physical_offset;
            out->virtual_size = data_size;
        }
    }

    free(physical_offsets);
    free(physical_sizes);
    free(data);
    free(compressed);
    fclose(entry_file);

    if (!ok)
    {
        free(nodes);
        free(entry_sets);
        free(out->bktr_header);
        remove(entry_filepath.char_path);
        memset(out, 0, sizeof(*out));
        return -1;
    }

    return 0;
}

void nca_compress_write(nca_compress_result_t *result, FILE *nca_file, filepath_t *temp_dir, nca_fs_header_t *fs_header, uint64_t table_offset, uint64_t entry_data_size)
{
    /* Layer layout relative to the section data start:
     *   [0]                  compressed entry data
     *   [table_offset]       node storage
     *   [table_offset+nodes] entry-set storage */
    (void)entry_data_size;

    /* Write the compressed entry data first. */
    filepath_t entry_filepath;
    filepath_init(&entry_filepath);
    filepath_copy(&entry_filepath, temp_dir);
    filepath_append(&entry_filepath, COMPRESS_ENTRY_TEMP_NAME);
    FILE *entry_file = os_fopen(entry_filepath.os_path, OS_MODE_READ);
    if (entry_file != NULL)
    {
        unsigned char *buf = (unsigned char *)malloc(0x100000);
        if (buf != NULL)
        {
            size_t read_size;
            while ((read_size = fread(buf, 1, 0x100000, entry_file)) > 0)
                fwrite(buf, read_size, 1, nca_file);
            free(buf);
        }
        fclose(entry_file);
        remove(entry_filepath.char_path);
    }

    /* Write the node storage, then the entry-set storage. */
    fwrite(result->nodes, 1, result->nodes_size, nca_file);
    fwrite(result->entry_sets, 1, result->entry_sets_size, nca_file);

    /* Fill in the FS header compression info (offset 0x178). */
    memset(&fs_header->compression_info, 0, sizeof(fs_header->compression_info));
    fs_header->compression_info.table_offset = table_offset;
    fs_header->compression_info.table_size = result->table_size;
    memcpy(fs_header->compression_info.table_header, result->bktr_header, sizeof(fs_header->compression_info.table_header));
}
