#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include "nca.h"
#include "bktr.h"
#include "sha.h"
#include "filepath.h"
#include "romfs.h"
#include "cnmt.h"
#include "ticket.h"
#include "rsa.h"

/* Builds the compression layer for a section's raw RomFS payload (IVFC level 6)
 * and updates `fs_header` to describe the compressed bytes. Returns the
 * compressed layer size, or 0 on failure. */
static uint64_t nca_build_section_compression(hp_settings_t *settings, filepath_t *romfs_path, filepath_t *out_path, nca_fs_header_t *fs_header)
{
    if (settings->compress_level <= 0)
        return 0;

    uint64_t virtual_size = fs_header->romfs_superblock.ivfc_header.level_headers[5].hash_data_size;
    nca_compress_result_t result;

    printf("Compressing IVFC level 6 (%" PRIu64 " bytes) with level %i\n", virtual_size, settings->compress_level);

    FILE *data_file = os_fopen(romfs_path->os_path, OS_MODE_READ);
    if (data_file == NULL)
    {
        fprintf(stderr, "Failed to open %s!\n", romfs_path->char_path);
        exit(EXIT_FAILURE);
    }

    if (nca_compress_build(data_file, virtual_size, settings->compress_level, &settings->temp_dir, &result) != 0)
    {
        fclose(data_file);
        fprintf(stderr, "Failed to build NCA compression layer!\n");
        exit(EXIT_FAILURE);
    }
    fclose(data_file);

    /* Write the layer to a temporary file so it can be hashed as level 6. */
    FILE *layer_file = os_fopen(out_path->os_path, OS_MODE_WRITE_EDIT);
    if (layer_file == NULL)
    {
        fprintf(stderr, "Failed to create %s!\n", out_path->char_path);
        exit(EXIT_FAILURE);
    }

    nca_compress_write(&result, layer_file, &settings->temp_dir, fs_header, result.table_offset, result.entry_data_size);

    fseeko64(layer_file, 0, SEEK_END);
    uint64_t compressed_size = (uint64_t)ftello64(layer_file);

    /* Pad to a 0x4000 multiple so level-4 hashes cover full blocks. The
     * reported level-6 size stays the unpadded compressed size. */
    uint64_t padding_size = NCA_COMPRESS_BLOCK_SIZE - (compressed_size % NCA_COMPRESS_BLOCK_SIZE);
    if (padding_size != NCA_COMPRESS_BLOCK_SIZE)
    {
        unsigned char *padding = (unsigned char *)calloc(1, (size_t)padding_size);
        fwrite(padding, 1, (size_t)padding_size, layer_file);
        free(padding);
    }

    fclose(layer_file);

    nca_compress_result_free(&result);
    return compressed_size;
}

/* Writes the section's IVFC level files (levels 1-6) to the NCA, in order. */
void nca_write_section_romfs(FILE *nca_file, filepath_t *ivfc_lvls_path)
{
    for (int c = 0; c < 6; c++)
    {
        printf("Writing %s to NCA\n", ivfc_lvls_path[c].char_path);
        nca_write_file(nca_file, &ivfc_lvls_path[c]);
    }
}

void nca_create_romfs_type(hp_settings_t *settings, char *nca_type)
{
    printf("----> Creating %s NCA:\n", nca_type);
    printf("===> Creating NCA header\n");
    nca_header_t nca_header;
    memset(&nca_header, 0, sizeof(nca_header));

    filepath_t romfs_nca_path;
    filepath_init(&romfs_nca_path);
    filepath_copy(&romfs_nca_path, &settings->out_dir);
    filepath_append(&romfs_nca_path, "%s.nca", nca_type);

    FILE *romfs_nca_file;
    romfs_nca_file = os_fopen(romfs_nca_path.os_path, OS_MODE_WRITE_EDIT);

    // Write placeholder for NCA header
    printf("Writing NCA header placeholder to %s\n", romfs_nca_path.char_path);
    if (romfs_nca_file != NULL)
        fwrite(&nca_header, 1, sizeof(nca_header), romfs_nca_file);
    else
    {
        fprintf(stderr, "Failed to create %s!\n", romfs_nca_path.char_path);
        exit(EXIT_FAILURE);
    }

    printf("\n---> Creating Section 0:");

    // Set IVFC levels temp filepaths
    filepath_t ivfc_lvls_path[6];
    for (int a = 0; a < 6; a++)
    {
        filepath_init(&ivfc_lvls_path[a]);
        filepath_copy(&ivfc_lvls_path[a], &settings->temp_dir);
        filepath_append(&ivfc_lvls_path[a], "%s_sec0_ivfc_lvl%i", nca_type, a + 1);
    }

    //Build RomFS
    printf("\n===> Building RomFS\n");
    romfs_build(&settings->romfs_dir, &ivfc_lvls_path[5], &nca_header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[5].hash_data_size);
    nca_header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[5].block_size = 0x0E; // 0x4000

    // Compress: replace level 6's data with the compression layer.
    if (settings->compress_level > 0)
    {
        filepath_t comp_layer_path;
        filepath_init(&comp_layer_path);
        filepath_copy(&comp_layer_path, &settings->temp_dir);
        filepath_append(&comp_layer_path, "%s_sec0_compressed", nca_type);

        uint64_t compressed_size = (uint64_t)nca_build_section_compression(settings, &ivfc_lvls_path[5], &comp_layer_path, &nca_header.fs_headers[0]);
        if (compressed_size == 0)
        {
            fprintf(stderr, "Failed to build NCA compression layer!\n");
            exit(EXIT_FAILURE);
        }

        filepath_copy(&ivfc_lvls_path[5], &comp_layer_path);
        nca_header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[5].hash_data_size = compressed_size;
    }

    // Create IVFC levels
    printf("\n===> Creating IVFC levels\n");
    for (int b = 4; b >= 0; b--)
    {
        printf("Writing %s\n", ivfc_lvls_path[b].char_path);
        ivfc_create_level(&ivfc_lvls_path[b], &ivfc_lvls_path[b + 1], &nca_header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[b].hash_data_size);
        nca_header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[b].block_size = 0x0E; // 0x4000
    }

    // Set IVFC levels logical offset
    nca_header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[0].logical_offset = 0;
    for (int i = 1; i <= 5; i++)
        nca_header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[i].logical_offset = nca_header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[i - 1].logical_offset + nca_header.fs_headers[0].romfs_superblock.ivfc_header.level_headers[i - 1].hash_data_size;

    // Write IVFC levels
    printf("\n===> Writing section 0 data\n");
    nca_write_section_romfs(romfs_nca_file, ivfc_lvls_path);

    // Write Padding if required
    nca_write_padding(romfs_nca_file);

    // Common values
    nca_header.magic = MAGIC_NCA3;
    nca_header.content_type = settings->nca_type;
    nca_header.sdk_version = settings->sdk_version;
    nca_header.title_id = settings->title_id;
    if (settings->nca_disttype == NCA_DISTRIBUTION_GAMECARD)
        nca_header.distribution = 1;
    nca_set_keygen(&nca_header, settings);

    nca_header.section_entries[0].media_start_offset = 0x6;                                        // 0xC00 / 0x200
    nca_header.section_entries[0].media_end_offset = (uint32_t)(ftello64(romfs_nca_file) / 0x200); // Section end offset / 200
    nca_header.section_entries[0]._0x8[0] = 0x1;                                                   // Always 1

    nca_header.fs_headers[0].hash_type = HASH_TYPE_ROMFS;
    nca_header.fs_headers[0].version = 0x2; // Always 2
    nca_header.fs_headers[0].romfs_superblock.ivfc_header.magic = MAGIC_IVFC;
    nca_header.fs_headers[0].romfs_superblock.ivfc_header.id = 0x20000; //Always 0x20000
    nca_header.fs_headers[0].romfs_superblock.ivfc_header.master_hash_size = 0x20;
    nca_header.fs_headers[0].romfs_superblock.ivfc_header.num_levels = 0x7;
    if (settings->plaintext == 0)
        nca_header.fs_headers[0].crypt_type = CRYPT_CTR;
    else
        nca_header.fs_headers[0].crypt_type = CRYPT_NONE;

    // Calculate master hash and section hash
    printf("\n===> Calculating Hashes:\n");
    printf("Calculating Master hash\n");
    ivfc_calculate_master_hash(&ivfc_lvls_path[0], nca_header.fs_headers[0].romfs_superblock.ivfc_header.master_hash);
    printf("Calculating Section hash\n");
    nca_calculate_section_hash(&nca_header.fs_headers[0], nca_header.section_hashes[0]);

    printf("\n---> Finalizing:\n");

    if (settings->has_title_key == 0)
        // Set encrypted key area key 2
        memcpy(nca_header.encrypted_keys[2], settings->keyareakey, 0x10);
    else
    {
        // Calculate RightsID
        for (int ridc = 0; ridc < 8; ridc++)
        {
            nca_header.rights_id[7 - ridc] = (settings->title_id >> (8 * ridc) & 0xff);
        }
        nca_header.rights_id[15] = (uint8_t)settings->keygeneration;
    }

    printf("===> Encrypting NCA\n");
    if (settings->plaintext == 0)
    {
        // Encrypt section 0
        printf("Encrypting section 0\n");
        nca_encrypt_section(romfs_nca_file, &nca_header, 0, settings);
    }

    // Crypto type
    printf("Getting NCA file size\n");
    fseeko64(romfs_nca_file, 0, SEEK_END);
    nca_header.nca_size = (uint64_t)ftello64(romfs_nca_file);
    if (settings->has_title_key == 0)
    {
        printf("Encrypting key area\n");
        nca_encrypt_key_area(&nca_header, settings);
    }
    else
    {
        // Create cert and tik
        ticket_create_cert(settings);
        ticket_create_tik(settings);
    }

    // Fill NCA signature
    if (settings->nca_sig1_private_key.valid == VALIDITY_INVALID)
    {
        printf("Generating signature\n");
        nca_generate_sig(nca_header.fixed_key_sig, settings);
    }
    else
    {
        // Sign header with specified private key
        printf("Signing NCA header\n");
        rsa_sign_with_file(&nca_header.magic, 0x200, nca_header.fixed_key_sig, 0x100, settings->nca_sig1_private_key.char_path);
    }

    // Encrypt header
    printf("Encrypting header\n");
    nca_encrypt_header(&nca_header, settings);

    // Write NCA header
    printf("\n===> Writing NCA header\n");
    printf("Writing NCA header to %s\n", romfs_nca_path.char_path);
    fseeko64(romfs_nca_file, 0, SEEK_SET);
    fwrite(&nca_header, 1, sizeof(nca_header), romfs_nca_file);

    // Calculate hash and nca size
    printf("\n===> Post creation process\n");
    printf("Calculating NCA hash\n");
    unsigned char nca_hash[0x20];
    nca_calculate_hash(romfs_nca_file, nca_hash);

    fclose(romfs_nca_file);

    // Rename ncatype.nca to ncaid.nca
    filepath_t romfs_nca_final_path;
    filepath_init(&romfs_nca_final_path);
    filepath_copy(&romfs_nca_final_path, &settings->out_dir);
    char romfs_nca_name[37];
    hexBinaryString(nca_hash, 16, romfs_nca_name, 33);
    strcat(romfs_nca_name, ".nca");
    romfs_nca_name[36] = '\0';
    printf("Renaming %s.nca to %s\n", nca_type, romfs_nca_name);
    filepath_append(&romfs_nca_final_path, "%s", romfs_nca_name);
    os_rename(romfs_nca_path.os_path, romfs_nca_final_path.os_path);
    printf("\n----> Created %s NCA: %s\n", nca_type, romfs_nca_final_path.char_path);
}

void nca_create_program(hp_settings_t *settings)
{
    printf("----> Creating Program NCA:\n");
    printf("===> Creating NCA header\n");
    nca_header_t nca_header;
    memset(&nca_header, 0, sizeof(nca_header));

    filepath_t program_nca_path;
    filepath_init(&program_nca_path);
    filepath_copy(&program_nca_path, &settings->out_dir);
    filepath_append(&program_nca_path, "Program.nca");

    FILE *program_nca_file;
    program_nca_file = os_fopen(program_nca_path.os_path, OS_MODE_WRITE_EDIT);

    // Write placeholder for NCA header
    printf("Writing NCA header placeholder to %s\n", program_nca_path.char_path);
    if (program_nca_file != NULL)
        fwrite(&nca_header, 1, sizeof(nca_header), program_nca_file);
    else
    {
        fprintf(stderr, "Failed to create %s!\n", program_nca_path.char_path);
        exit(EXIT_FAILURE);
    }

    printf("\n---> Creating Section 0:");

    //Build ExeFS
    filepath_t program_exefs;
    filepath_init(&program_exefs);
    filepath_copy(&program_exefs, &settings->temp_dir);
    filepath_append(&program_exefs, "program_sec0_exefs");
    filepath_t program_exefs_hash_table;
    filepath_init(&program_exefs_hash_table);
    filepath_copy(&program_exefs_hash_table, &settings->temp_dir);
    filepath_append(&program_exefs_hash_table, "program_sec0_exefs_hashtable");
    uint32_t exefs_hash_block_size = PFS0_EXEFS_HASH_BLOCK_SIZE;
    printf("\n===> Building ExeFS\n");
    pfs0_build(&settings->exefs_dir, &program_exefs, &nca_header.fs_headers[0].pfs0_superblock.pfs0_size);
    printf("Calculating hash table\n");
    pfs0_create_hashtable(&program_exefs, &program_exefs_hash_table, exefs_hash_block_size, &nca_header.fs_headers[0].pfs0_superblock.hash_table_size, &nca_header.fs_headers[0].pfs0_superblock.pfs0_offset);

    // Write ExeFS
    printf("\n===> Writing ExeFS\n");
    printf("Writing PFS0 hash table\n");
    nca_write_file(program_nca_file, &program_exefs_hash_table);
    printf("Writing PFS0\n");
    nca_write_file(program_nca_file, &program_exefs);

    // Write Padding if required
    nca_write_padding(program_nca_file);

    // Common values
    nca_header.magic = MAGIC_NCA3;
    nca_header.content_type = 0x0; // Program
    nca_header.sdk_version = settings->sdk_version;
    nca_header.title_id = settings->title_id;
    if (settings->nca_disttype == NCA_DISTRIBUTION_GAMECARD)
        nca_header.distribution = 1;
    nca_set_keygen(&nca_header, settings);

    nca_header.section_entries[0].media_start_offset = 0x6;                                          // 0xC00 / 0x200
    nca_header.section_entries[0].media_end_offset = (uint32_t)(ftello64(program_nca_file) / 0x200); // Section end offset / 200
    nca_header.section_entries[0]._0x8[0] = 0x1;                                                     // Always 1

    nca_header.fs_headers[0].hash_type = HASH_TYPE_PFS0;
    nca_header.fs_headers[0].fs_type = FS_TYPE_PFS0;
    nca_header.fs_headers[0].version = 0x2; // Always 2
    nca_header.fs_headers[0].pfs0_superblock.always_2 = 0x2;
    nca_header.fs_headers[0].pfs0_superblock.block_size = exefs_hash_block_size;
    if (settings->plaintext == 0)
        nca_header.fs_headers[0].crypt_type = CRYPT_CTR;
    else
        nca_header.fs_headers[0].crypt_type = CRYPT_NONE;

    // Calculate master hash and section hash
    printf("\n===> Calculating Hashes:\n");
    printf("Calculating Master hash\n");
    pfs0_calculate_master_hash(&program_exefs_hash_table, nca_header.fs_headers[0].pfs0_superblock.hash_table_size, nca_header.fs_headers[0].pfs0_superblock.master_hash);
    printf("Calculating Section hash\n");
    nca_calculate_section_hash(&nca_header.fs_headers[0], nca_header.section_hashes[0]);

    if (settings->romfs_dir.valid == VALIDITY_VALID)
    {

        printf("\n---> Creating Section 1:");

        // Set IVFC levels temp filepaths
        filepath_t ivfc_lvls_path[6];
        for (int a = 0; a < 6; a++)
        {
            filepath_init(&ivfc_lvls_path[a]);
            filepath_copy(&ivfc_lvls_path[a], &settings->temp_dir);
            filepath_append(&ivfc_lvls_path[a], "program_sec1_ivfc_lvl%i", a + 1);
        }

        //Build RomFS
        printf("\n===> Building RomFS\n");
        romfs_build(&settings->romfs_dir, &ivfc_lvls_path[5], &nca_header.fs_headers[1].romfs_superblock.ivfc_header.level_headers[5].hash_data_size);
        nca_header.fs_headers[1].romfs_superblock.ivfc_header.level_headers[5].block_size = 0x0E; // 0x4000

        // Compress: replace level 6's data with the compression layer.
        if (settings->compress_level > 0)
        {
            filepath_t comp_layer_path;
            filepath_init(&comp_layer_path);
            filepath_copy(&comp_layer_path, &settings->temp_dir);
            filepath_append(&comp_layer_path, "program_sec1_compressed");

            uint64_t compressed_size = nca_build_section_compression(settings, &ivfc_lvls_path[5], &comp_layer_path, &nca_header.fs_headers[1]);
            if (compressed_size == 0)
            {
                fprintf(stderr, "Failed to build NCA compression layer!\n");
                exit(EXIT_FAILURE);
            }

            filepath_copy(&ivfc_lvls_path[5], &comp_layer_path);
            nca_header.fs_headers[1].romfs_superblock.ivfc_header.level_headers[5].hash_data_size = compressed_size;
        }

        // Create IVFC levels
        printf("\n===> Creating IVFC levels\n");
        for (int b = 4; b >= 0; b--)
        {
            printf("Writing %s\n", ivfc_lvls_path[b].char_path);
            ivfc_create_level(&ivfc_lvls_path[b], &ivfc_lvls_path[b + 1], &nca_header.fs_headers[1].romfs_superblock.ivfc_header.level_headers[b].hash_data_size);
            nca_header.fs_headers[1].romfs_superblock.ivfc_header.level_headers[b].block_size = 0x0E; // 0x4000
        }

        // Set IVFC levels logical offset
        nca_header.fs_headers[1].romfs_superblock.ivfc_header.level_headers[0].logical_offset = 0;
        for (int i = 1; i <= 5; i++)
            nca_header.fs_headers[1].romfs_superblock.ivfc_header.level_headers[i].logical_offset = nca_header.fs_headers[1].romfs_superblock.ivfc_header.level_headers[i - 1].logical_offset + nca_header.fs_headers[1].romfs_superblock.ivfc_header.level_headers[i - 1].hash_data_size;

        // Write IVFC levels
        printf("\n===> Writing section 1 data\n");
        nca_write_section_romfs(program_nca_file, ivfc_lvls_path);

        // Write Padding if required
        nca_write_padding(program_nca_file);

        // Set header values
        nca_header.section_entries[1].media_start_offset = nca_header.section_entries[0].media_end_offset;
        nca_header.section_entries[1].media_end_offset = (uint32_t)(ftello64(program_nca_file) / 0x200);
        nca_header.section_entries[1]._0x8[0] = 0x1; // Always 1

        nca_header.fs_headers[1].hash_type = HASH_TYPE_ROMFS;
        nca_header.fs_headers[1].version = 0x2; // Always 2
        nca_header.fs_headers[1].romfs_superblock.ivfc_header.magic = MAGIC_IVFC;
        nca_header.fs_headers[1].romfs_superblock.ivfc_header.id = 0x20000; //Always 0x20000
        nca_header.fs_headers[1].romfs_superblock.ivfc_header.master_hash_size = 0x20;
        nca_header.fs_headers[1].romfs_superblock.ivfc_header.num_levels = 0x7;
        if (settings->plaintext == 0)
            nca_header.fs_headers[1].crypt_type = CRYPT_CTR;
        else
            nca_header.fs_headers[1].crypt_type = CRYPT_NONE;

        // Calculate master hash and section hash
        printf("\n===> Calculating Hashes:\n");
        printf("Calculating Master hash\n");
        ivfc_calculate_master_hash(&ivfc_lvls_path[0], nca_header.fs_headers[1].romfs_superblock.ivfc_header.master_hash);
        printf("Calculating Section hash\n");
        nca_calculate_section_hash(&nca_header.fs_headers[1], nca_header.section_hashes[1]);
    }

    if (settings->logo_dir.valid == VALIDITY_VALID)
    {
        printf("\n---> Creating Section 2:");

        //Build logo
        filepath_t program_logo;
        filepath_init(&program_logo);
        filepath_copy(&program_logo, &settings->temp_dir);
        filepath_append(&program_logo, "program_sec2_logo");
        filepath_t program_logo_hash_table;
        filepath_init(&program_logo_hash_table);
        filepath_copy(&program_logo_hash_table, &settings->temp_dir);
        filepath_append(&program_logo_hash_table, "program_sec2_logo_hashtable");
        uint32_t logo_hash_block_size = PFS0_LOGO_HASH_BLOCK_SIZE;
        printf("\n===> Building PFS0\n");
        pfs0_build(&settings->logo_dir, &program_logo, &nca_header.fs_headers[2].pfs0_superblock.pfs0_size);
        printf("Calculating hash table\n");
        pfs0_create_hashtable(&program_logo, &program_logo_hash_table, logo_hash_block_size, &nca_header.fs_headers[2].pfs0_superblock.hash_table_size, &nca_header.fs_headers[2].pfs0_superblock.pfs0_offset);

        // Write PFS0
        printf("\n===> Writing Logo\n");
        printf("Writing PFS0 hash table\n");
        nca_write_file(program_nca_file, &program_logo_hash_table);
        printf("Writing PFS0\n");
        nca_write_file(program_nca_file, &program_logo);

        // Write Padding if required
        nca_write_padding(program_nca_file);

        if (settings->romfs_dir.valid == VALIDITY_VALID)
            nca_header.section_entries[2].media_start_offset = nca_header.section_entries[1].media_end_offset;
        else
            nca_header.section_entries[2].media_start_offset = nca_header.section_entries[0].media_end_offset;

        nca_header.section_entries[2].media_end_offset = (uint32_t)(ftello64(program_nca_file) / 0x200); // Section end offset / 200
        nca_header.section_entries[2]._0x8[0] = 0x1;                                                     // Always 1

        nca_header.fs_headers[2].hash_type = HASH_TYPE_PFS0;
        nca_header.fs_headers[2].fs_type = FS_TYPE_PFS0;
        nca_header.fs_headers[2].version = 0x2;    // Always 2
        nca_header.fs_headers[2].crypt_type = 0x1; // Plain text
        nca_header.fs_headers[2].pfs0_superblock.always_2 = 0x2;
        nca_header.fs_headers[2].pfs0_superblock.block_size = logo_hash_block_size;

        // Calculate master hash and section hash
        printf("\n===> Calculating Hashes:\n");
        printf("Calculating Master hash\n");
        pfs0_calculate_master_hash(&program_logo_hash_table, nca_header.fs_headers[2].pfs0_superblock.hash_table_size, nca_header.fs_headers[2].pfs0_superblock.master_hash);
        printf("Calculating Section hash\n");
        nca_calculate_section_hash(&nca_header.fs_headers[2], nca_header.section_hashes[2]);
    }

    printf("\n---> Finalizing:\n");

    if (settings->has_title_key == 0)
        // Set encrypted key area key 2
        memcpy(nca_header.encrypted_keys[2], settings->keyareakey, 0x10);
    else
    {
        // Calculate RightsID
        for (int ridc = 0; ridc < 8; ridc++)
        {
            nca_header.rights_id[7 - ridc] = (settings->title_id >> (8 * ridc) & 0xff);
        }
        nca_header.rights_id[15] = (uint8_t)settings->keygeneration;
    }

    printf("===> Encrypting NCA\n");
    // Encrypt sections
    if (settings->plaintext == 0)
    {
        printf("Encrypting section 0\n");
        nca_encrypt_section(program_nca_file, &nca_header, 0, settings);
        if (settings->romfs_dir.valid == VALIDITY_VALID)
        {
            printf("Encrypting section 1\n");
            nca_encrypt_section(program_nca_file, &nca_header, 1, settings);
        }
    }

    // Crypto type
    printf("Getting NCA file size\n");
    fseeko64(program_nca_file, 0, SEEK_END);
    nca_header.nca_size = (uint64_t)ftello64(program_nca_file);
    if (settings->has_title_key == 0)
    {
        printf("Encrypting key area\n");
        nca_encrypt_key_area(&nca_header, settings);
    }
    else
    {
        // Create cert and tik
        ticket_create_cert(settings);
        ticket_create_tik(settings);
    }

    // Fill NCA signature
    if (settings->nca_sig1_private_key.valid == VALIDITY_INVALID)
    {
        printf("Generating signature\n");
        nca_generate_sig(nca_header.fixed_key_sig, settings);
    }
    else
    {
        // Sign header with specified private key
        printf("Signing NCA header\n");
        rsa_sign_with_file(&nca_header.magic, 0x200, nca_header.fixed_key_sig, 0x100, settings->nca_sig1_private_key.char_path);
    }

    // Sign header with acid public key (signature 2)
    if ((settings->noselfsignncasig2) == 0 || (settings->nca_sig2_private_key.valid == VALIDITY_VALID))
    {
        printf("Signing NCA header signature 2\n");
        if (settings->nca_sig2_private_key.valid == VALIDITY_VALID)
            rsa_sign_with_file(&nca_header.magic, 0x200, (unsigned char *)&nca_header.npdm_key_sig, 0x100, settings->nca_sig2_private_key.char_path);
        else
            rsa_sign(&nca_header.magic, 0x200, (unsigned char *)&nca_header.npdm_key_sig, 0x100, (char *)rsa_get_acid_private_key());
    }

    printf("Encrypting header\n");
    nca_encrypt_header(&nca_header, settings);

    // Write NCA header
    printf("\n===> Writing NCA header\n");
    printf("Writing NCA header to %s\n", program_nca_path.char_path);
    fseeko64(program_nca_file, 0, SEEK_SET);
    fwrite(&nca_header, 1, sizeof(nca_header), program_nca_file);

    // Calculate hash and nca size
    printf("\n===> Post creation process\n");
    printf("Calculating NCA hash\n");
    unsigned char nca_hash[0x20];
    nca_calculate_hash(program_nca_file, nca_hash);

    fclose(program_nca_file);

    // Rename Program.nca to ncaid.nca
    filepath_t program_nca_final_path;
    filepath_init(&program_nca_final_path);
    filepath_copy(&program_nca_final_path, &settings->out_dir);
    char program_nca_name[37];
    hexBinaryString(nca_hash, 16, program_nca_name, 33);
    strcat(program_nca_name, ".nca");
    program_nca_name[36] = '\0';
    printf("Renaming Program.nca to %s\n", program_nca_name);
    filepath_append(&program_nca_final_path, "%s", program_nca_name);
    os_rename(program_nca_path.os_path, program_nca_final_path.os_path);
    printf("\n----> Created Program NCA: %s\n", program_nca_final_path.char_path);
}

void nca_create_meta(hp_settings_t *settings)
{
    printf("----> Creating metadata NCA:\n");
    printf("===> Creating NCA header\n");
    nca_header_t nca_header;
    memset(&nca_header, 0, sizeof(nca_header));

    filepath_t meta_nca_path;
    filepath_init(&meta_nca_path);
    filepath_copy(&meta_nca_path, &settings->out_dir);
    filepath_append(&meta_nca_path, "Meta.nca");

    FILE *meta_nca_file;
    meta_nca_file = os_fopen(meta_nca_path.os_path, OS_MODE_WRITE_EDIT);

    // Write placeholder for NCA header
    printf("Writing NCA header placeholder to %s\n", meta_nca_path.char_path);
    if (meta_nca_file != NULL)
        fwrite(&nca_header, 1, sizeof(nca_header), meta_nca_file);
    else
    {
        fprintf(stderr, "Failed to create %s!\n", meta_nca_path.char_path);
        exit(EXIT_FAILURE);
    }

    filepath_t cnmt_path;
    filepath_init(&cnmt_path);
    filepath_copy(&cnmt_path, &settings->temp_dir);
    filepath_append(&cnmt_path, "cnmt");
    filepath_t cnmt_dir_path;
    filepath_init(&cnmt_dir_path);
    filepath_copy(&cnmt_dir_path, &cnmt_path);
    // Create cnmt directory if required
    os_makedir(cnmt_dir_path.os_path);
    // Cnmt filename = titletype_tid.cnmt
    printf("\n===> Creating Metadata file\n");
    if (settings->title_type == TITLE_TYPE_APPLICATION)
    {
        filepath_append(&cnmt_path, "Application_%016" PRIx64 ".cnmt", settings->title_id);
        if (settings->cnmt.valid == VALIDITY_VALID)
        {
            printf("Copying %s to %s\n", settings->cnmt.char_path, cnmt_path.char_path);
            filepath_copy_file(&settings->cnmt, &cnmt_path);
        }
        else
            cnmt_create_application(&cnmt_path, settings);
    }
    else if (settings->title_type == TITLE_TYPE_ADDON)
    {
        filepath_append(&cnmt_path, "AddOnContent_%016" PRIx64 ".cnmt", settings->title_id);
        if (settings->cnmt.valid == VALIDITY_VALID)
        {
            printf("Copying %s to %s\n", settings->cnmt.char_path, cnmt_path.char_path);
            filepath_copy_file(&settings->cnmt, &cnmt_path);
        }
        else
            cnmt_create_addon(&cnmt_path, settings);
    }
    else if (settings->title_type == TITLE_TYPE_SYSTEMPROGRAM)
    {
        filepath_append(&cnmt_path, "SystemProgram_%016" PRIx64 ".cnmt", settings->title_id);
        if (settings->cnmt.valid == VALIDITY_VALID)
        {
            printf("Copying %s to %s\n", settings->cnmt.char_path, cnmt_path.char_path);
            filepath_copy_file(&settings->cnmt, &cnmt_path);
        }
        else
            cnmt_create_systemprogram(&cnmt_path, settings);
    }
    else if (settings->title_type == TITLE_TYPE_SYSTEMDATA)
    {
        filepath_append(&cnmt_path, "SystemData_%016" PRIx64 ".cnmt", settings->title_id);
        if (settings->cnmt.valid == VALIDITY_VALID)
        {
            printf("Copying %s to %s\n", settings->cnmt.char_path, cnmt_path.char_path);
            filepath_copy_file(&settings->cnmt, &cnmt_path);
        }
        else
            cnmt_create_systemdata(&cnmt_path, settings);
    }
    else if (settings->title_type == TITLE_TYPE_PATCH)
    {
        filepath_append(&cnmt_path, "Patch_%016" PRIx64 ".cnmt", settings->title_id);
        if (settings->cnmt.valid == VALIDITY_VALID)
        {
            printf("Copying %s to %s\n", settings->cnmt.char_path, cnmt_path.char_path);
            filepath_copy_file(&settings->cnmt, &cnmt_path);
        }
        else
        {
            fprintf(stderr, "Creating Patch metadata without providing cnmt is not supported yet!\n");
            exit(EXIT_FAILURE);
        }
    }

    //Build PFS0
    filepath_t meta_pfs0;
    filepath_init(&meta_pfs0);
    filepath_copy(&meta_pfs0, &settings->temp_dir);
    filepath_append(&meta_pfs0, "meta_sec0_pfs0");
    filepath_t meta_pfs0_hash_table;
    filepath_init(&meta_pfs0_hash_table);
    filepath_copy(&meta_pfs0_hash_table, &settings->temp_dir);
    filepath_append(&meta_pfs0_hash_table, "meta_sec0_pfs0_hashtable");
    uint32_t meta_hash_block_size = PFS0_META_HASH_BLOCK_SIZE;
    printf("\n===> Building PFS0\n");
    pfs0_build(&cnmt_dir_path, &meta_pfs0, &nca_header.fs_headers[0].pfs0_superblock.pfs0_size);
    printf("Calculating hash table\n");
    pfs0_create_hashtable(&meta_pfs0, &meta_pfs0_hash_table, meta_hash_block_size, &nca_header.fs_headers[0].pfs0_superblock.hash_table_size, &nca_header.fs_headers[0].pfs0_superblock.pfs0_offset);

    // Write ExeFS
    printf("\n===> Writing PFS0 section\n");
    printf("Writing PFS0 hash table\n");
    nca_write_file(meta_nca_file, &meta_pfs0_hash_table);
    printf("Writing PFS0\n");
    nca_write_file(meta_nca_file, &meta_pfs0);

    // Write Padding if required
    nca_write_padding(meta_nca_file);

    // Common values
    nca_header.magic = MAGIC_NCA3;
    nca_header.content_type = 0x1; // Meta
    nca_header.sdk_version = settings->sdk_version;
    nca_header.title_id = settings->title_id;
    if (settings->nca_disttype == NCA_DISTRIBUTION_GAMECARD)
        nca_header.distribution = 1;
    nca_set_keygen(&nca_header, settings);

    nca_header.section_entries[0].media_start_offset = 0x6;                                       // 0xC00 / 0x200
    nca_header.section_entries[0].media_end_offset = (uint32_t)(ftello64(meta_nca_file) / 0x200); // Section end offset / 200
    nca_header.section_entries[0]._0x8[0] = 0x1;                                                  // Always 1

    nca_header.fs_headers[0].hash_type = HASH_TYPE_PFS0;
    nca_header.fs_headers[0].fs_type = FS_TYPE_PFS0;
    nca_header.fs_headers[0].version = 0x2; // Always 2
    nca_header.fs_headers[0].pfs0_superblock.always_2 = 0x2;
    nca_header.fs_headers[0].pfs0_superblock.block_size = meta_hash_block_size;
    if (settings->plaintext == 0)
        nca_header.fs_headers[0].crypt_type = CRYPT_CTR;
    else
        nca_header.fs_headers[0].crypt_type = CRYPT_NONE;

    // Calculate master hash and section hash
    printf("\n===> Calculating Hashes:\n");
    printf("Calculating Master hash\n");
    pfs0_calculate_master_hash(&meta_pfs0_hash_table, nca_header.fs_headers[0].pfs0_superblock.hash_table_size, nca_header.fs_headers[0].pfs0_superblock.master_hash);
    printf("Calculating Section hash\n");
    nca_calculate_section_hash(&nca_header.fs_headers[0], nca_header.section_hashes[0]);

    printf("\n---> Finalizing:\n");

    // Set encrypted key area key 2
    memcpy(nca_header.encrypted_keys[2], settings->keyareakey, 0x10);

    printf("===> Encrypting NCA\n");
    if (settings->plaintext == 0)
    {
        // Encrypt section 0
        printf("Encrypting section 0\n");
        nca_encrypt_section(meta_nca_file, &nca_header, 0, settings);
    }

    // Encrypt kek
    printf("Getting NCA file size\n");
    fseeko64(meta_nca_file, 0, SEEK_END);
    nca_header.nca_size = (uint64_t)ftello64(meta_nca_file);
    printf("Encrypting key area\n");
    nca_encrypt_key_area(&nca_header, settings);

    // Fill NCA signature
    if (settings->nca_sig1_private_key.valid == VALIDITY_INVALID)
    {
        printf("Generating signature\n");
        nca_generate_sig(nca_header.fixed_key_sig, settings);
    }
    else
    {
        // Sign header with specified private key
        printf("Signing NCA header\n");
        rsa_sign_with_file(&nca_header.magic, 0x200, nca_header.fixed_key_sig, 0x100, settings->nca_sig1_private_key.char_path);
    }

    // Encrypt header
    printf("Encrypting header\n");
    nca_encrypt_header(&nca_header, settings);

    // Write NCA header
    printf("\n===> Writing NCA header\n");
    printf("Writing NCA header to %s\n", meta_nca_path.char_path);
    fseeko64(meta_nca_file, 0, SEEK_SET);
    fwrite(&nca_header, 1, sizeof(nca_header), meta_nca_file);

    // Calculate hash and nca size
    printf("\n===> Post creation process\n");
    printf("Calculating NCA hash\n");
    unsigned char nca_hash[0x20];
    nca_calculate_hash(meta_nca_file, nca_hash);

    fclose(meta_nca_file);

    // Rename Meta.nca to ncaid.cnmt.nca
    filepath_t meta_nca_final_path;
    filepath_init(&meta_nca_final_path);
    filepath_copy(&meta_nca_final_path, &settings->out_dir);
    char meta_nca_name[42];
    hexBinaryString(nca_hash, 16, meta_nca_name, 33);
    strcat(meta_nca_name, ".cnmt.nca");
    meta_nca_name[41] = '\0';
    printf("Renaming Meta.nca to %s\n", meta_nca_name);
    filepath_append(&meta_nca_final_path, "%s", meta_nca_name);
    os_rename(meta_nca_path.os_path, meta_nca_final_path.os_path);
    printf("\n----> Created metadata NCA: %s\n", meta_nca_final_path.char_path);
}

void nca_write_file(FILE *nca_file, filepath_t *file_path)
{
    uint64_t file_size;
    FILE *fl;
    fl = os_fopen(file_path->os_path, OS_MODE_READ);

    if (fl == NULL)
    {
        fprintf(stderr, "Failed to open %s!\n", file_path->char_path);
        exit(EXIT_FAILURE);
    }

    // Get IVFC level file filesize
    fseeko64(fl, 0, SEEK_END);
    file_size = ftello64(fl);
    fseeko64(fl, 0, SEEK_SET);

    uint64_t read_size = 0x61A8000; // 100 MB buffer.
    unsigned char *buf = malloc(read_size);
    if (buf == NULL)
    {
        fprintf(stderr, "Failed to allocate file-read buffer!\n");
        exit(EXIT_FAILURE);
    }

    uint64_t ofs = 0;
    while (ofs < file_size)
    {
        if (ofs + read_size >= file_size)
            read_size = file_size - ofs;
        if (fread(buf, 1, read_size, fl) != read_size)
        {
            fprintf(stderr, "Failed to read file %s\n", file_path->char_path);
            exit(EXIT_FAILURE);
        }
        fwrite(buf, read_size, 1, nca_file);
        ofs += read_size;
    }

    free(buf);
    fclose(fl);
}

// Write padding for media_end_offset
void nca_write_padding(FILE *nca_file)
{
    unsigned char *buf = (unsigned char *)calloc(1, 0x200);
    uint64_t curr_offset = ftello64(nca_file);
    uint64_t block_size = 0x200;
    uint64_t padding_size = block_size - (curr_offset % block_size);
    if (curr_offset % block_size != 0)
        fwrite(buf, 1, padding_size, nca_file);
    free(buf);
}

void nca_calculate_section_hash(nca_fs_header_t *fs_header, uint8_t *out_section_hash)
{
    // Calculate hash
    sha_ctx_t *sha_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
    sha_update(sha_ctx, fs_header, 0x200);
    sha_get_hash(sha_ctx, (unsigned char *)out_section_hash);
    free_sha_ctx(sha_ctx);
}

void nca_encrypt_key_area(nca_header_t *nca_header, hp_settings_t *settings)
{
    aes_ctx_t *aes_ctx = new_aes_ctx(settings->keyset.key_area_keys[settings->keygeneration - 1][0], 16, AES_MODE_ECB);
    aes_encrypt(aes_ctx, nca_header->encrypted_keys, nca_header->encrypted_keys, 0x40);
    free_aes_ctx(aes_ctx);
}

void nca_encrypt_header(nca_header_t *nca_header, hp_settings_t *settings)
{
    aes_ctx_t *hdr_aes_ctx = new_aes_ctx(settings->keyset.header_key, 32, AES_MODE_XTS);
    aes_xts_encrypt(hdr_aes_ctx, nca_header, nca_header, 0xC00, 0, 0x200);
    free_aes_ctx(hdr_aes_ctx);
}

void nca_encrypt_section(FILE *nca_file, nca_header_t *nca_header, uint8_t section_index, hp_settings_t *settings)
{
    uint64_t start_offset = nca_header->section_entries[section_index].media_start_offset;
    start_offset *= 0x200;
    uint64_t end_offset = nca_header->section_entries[section_index].media_end_offset;
    end_offset *= 0x200;
    uint64_t filesize = end_offset - start_offset;

    // Calculate counter for section encryption
    uint64_t ctr_ofs = start_offset >> 4;
    unsigned char ctr[0x10] = {0};
    for (unsigned int j = 0; j < 0x8; j++)
    {
        ctr[j] = nca_header->fs_headers[section_index].section_ctr[0x8 - j - 1];
        ctr[0x10 - j - 1] = (unsigned char)(ctr_ofs & 0xFF);
        ctr_ofs >>= 8;
    }

    uint64_t read_size = 0x6000000; //~100 MB buffer.
    unsigned char *buf = malloc(read_size);
    if (buf == NULL)
    {
        fprintf(stderr, "Failed to allocate file-read buffer!\n");
        exit(EXIT_FAILURE);
    }

    // Set Section encryption key
    unsigned char enc_key[0x10];
    if (settings->has_title_key == 1)
        memcpy(enc_key, settings->title_key, 0x10);
    else
        memcpy(enc_key, nca_header->encrypted_keys[2], 0x10);
    aes_ctx_t *aes_ctx = new_aes_ctx(enc_key, 16, AES_MODE_CTR);

    uint64_t ofs = 0;
    fseeko64(nca_file, start_offset, SEEK_SET);
    while (ofs < filesize)
    {
        if (ofs + read_size >= filesize)
            read_size = filesize - ofs;
        if (fread(buf, 1, read_size, nca_file) != read_size)
        {
            fprintf(stderr, "Failed to read file!\n");
            exit(EXIT_FAILURE);
        }
        fseeko64(nca_file, start_offset + ofs, SEEK_SET);
        aes_setiv(aes_ctx, ctr, 0x10);
        aes_encrypt(aes_ctx, buf, buf, read_size);
        fwrite(buf, 1, read_size, nca_file);
        ofs += read_size;
        nca_update_ctr(ctr, start_offset + ofs);
    }

    free(buf);
    free_aes_ctx(aes_ctx);
}

/* Updates the CTR for an offset. */
void nca_update_ctr(unsigned char *ctr, uint64_t ofs)
{
    ofs >>= 4;
    for (unsigned int j = 0; j < 0x8; j++)
    {
        ctr[0x10 - j - 1] = (unsigned char)(ofs & 0xFF);
        ofs >>= 8;
    }
}

void nca_calculate_hash(FILE *nca_file, unsigned char *out_nca_hash)
{
    uint64_t file_size;
    // Get source file size
    fseeko64(nca_file, 0, SEEK_END);
    file_size = (uint64_t)ftello64(nca_file);

    sha_ctx_t *sha_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
    uint64_t read_size = 0x61A8000; // 100 MB buffer.
    unsigned char *buf = malloc(read_size);
    fseeko64(nca_file, 0, SEEK_SET);

    if (buf == NULL)
    {
        fprintf(stderr, "Failed to allocate file-read buffer!\n");
        exit(EXIT_FAILURE);
    }

    uint64_t ofs = 0;
    while (ofs < file_size)
    {
        if (ofs + read_size >= file_size)
            read_size = file_size - ofs;
        if (fread(buf, 1, read_size, nca_file) != read_size)
        {
            fprintf(stderr, "Failed to read file!\n");
            exit(EXIT_FAILURE);
        }
        sha_update(sha_ctx, buf, read_size);
        ofs += read_size;
    }
    sha_get_hash(sha_ctx, out_nca_hash);

    free(buf);
    free_sha_ctx(sha_ctx);
}

void nca_set_keygen(nca_header_t *nca_header, hp_settings_t *settings)
{
    if (settings->keygeneration != 1)
    {
        if (settings->keygeneration == 2)
            nca_header->crypto_type = 0x2;
        else
        {
            nca_header->crypto_type = 0x2;
            nca_header->crypto_type2 = settings->keygeneration;
        }
    }
}

void nca_generate_sig(uint8_t *nca_sig, hp_settings_t *settings)
{
    switch (settings->nca_sig)
    {
    case NCA_SIG_TYPE_STATIC:
        memset(nca_sig, 4, 0x100);
        break;
    case NCA_SIG_TYPE_RANDOM:
        srand(time(NULL));
        for (long nsigc = 0; nsigc < 0x100; nsigc++)
            nca_sig[nsigc] = rand() % 0xff;
        break;
    case NCA_SIG_TYPE_ZERO:
        break;
    }
}

char *nca_romfs_get_type(uint8_t type)
{
    switch (type)
    {
    case NCA_TYPE_CONTROL:
        return "Control";
        break;
    case NCA_TYPE_DATA:
        return "Data";
        break;
    case NCA_TYPE_MANUAL:
        return "Manual";
        break;
    case NCA_TYPE_PUBLICDATA:
        return "PublicData";
        break;
    default:
        fprintf(stderr, "Unknown NCA type\n");
        exit(EXIT_FAILURE);
    }
}