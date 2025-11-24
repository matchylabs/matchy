/* MaxMind DB Compatibility Layer
 * 
 * This header provides libmaxminddb API compatibility, powered by matchy.
 * 
 * Usage:
 *   Instead of: #include <maxminddb.h>
 *   Use:        #include <matchy/maxminddb.h>
 * 
 * Then link with -lmatchy instead of -lmaxminddb
 * 
 * Most libmaxminddb applications will work with just these changes.
 */

#ifndef MAXMINDDB_COMPAT_H
#define MAXMINDDB_COMPAT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #if defined(_MSC_VER)
        #define ssize_t SSIZE_T
    #endif
#else
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
#endif

/* Include matchy's native API (we use it internally) */
#include "matchy.h"

/* ========================================================================
 * CONSTANTS AND ERROR CODES
 * ======================================================================== */

/* Data type constants (map to matchy types) */
#define MMDB_DATA_TYPE_EXTENDED         MATCHY_DATA_TYPE_EXTENDED
#define MMDB_DATA_TYPE_POINTER          MATCHY_DATA_TYPE_POINTER
#define MMDB_DATA_TYPE_UTF8_STRING      MATCHY_DATA_TYPE_UTF8_STRING
#define MMDB_DATA_TYPE_DOUBLE           MATCHY_DATA_TYPE_DOUBLE
#define MMDB_DATA_TYPE_BYTES            MATCHY_DATA_TYPE_BYTES
#define MMDB_DATA_TYPE_UINT16           MATCHY_DATA_TYPE_UINT16
#define MMDB_DATA_TYPE_UINT32           MATCHY_DATA_TYPE_UINT32
#define MMDB_DATA_TYPE_MAP              MATCHY_DATA_TYPE_MAP
#define MMDB_DATA_TYPE_INT32            MATCHY_DATA_TYPE_INT32
#define MMDB_DATA_TYPE_UINT64           MATCHY_DATA_TYPE_UINT64
#define MMDB_DATA_TYPE_UINT128          MATCHY_DATA_TYPE_UINT128
#define MMDB_DATA_TYPE_ARRAY            MATCHY_DATA_TYPE_ARRAY
#define MMDB_DATA_TYPE_BOOLEAN          MATCHY_DATA_TYPE_BOOLEAN
#define MMDB_DATA_TYPE_FLOAT            MATCHY_DATA_TYPE_FLOAT

/* Record type constants */
#define MMDB_RECORD_TYPE_SEARCH_NODE    0
#define MMDB_RECORD_TYPE_EMPTY          1
#define MMDB_RECORD_TYPE_DATA           2
#define MMDB_RECORD_TYPE_INVALID        3

/* Open mode flags */
#define MMDB_MODE_MMAP                  1
#define MMDB_MODE_MASK                  7

/* Error codes (map to matchy error codes) */
#define MMDB_SUCCESS                    0
#define MMDB_FILE_OPEN_ERROR            1
#define MMDB_CORRUPT_SEARCH_TREE_ERROR  2
#define MMDB_INVALID_METADATA_ERROR     3
#define MMDB_IO_ERROR                   4
#define MMDB_OUT_OF_MEMORY_ERROR        5
#define MMDB_UNKNOWN_DATABASE_FORMAT_ERROR 6
#define MMDB_INVALID_DATA_ERROR         7
#define MMDB_INVALID_LOOKUP_PATH_ERROR  8
#define MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR 9
#define MMDB_INVALID_NODE_NUMBER_ERROR  10
#define MMDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR 11

/* ========================================================================
 * TYPE DEFINITIONS
 * ======================================================================== */

/* Forward declarations */
typedef struct MMDB_s MMDB_s;
typedef struct MMDB_entry_s MMDB_entry_s;
typedef struct MMDB_lookup_result_s MMDB_lookup_result_s;
typedef struct MMDB_entry_data_s MMDB_entry_data_s;
typedef struct MMDB_entry_data_list_s MMDB_entry_data_list_s;

/* Main database handle
 * 
 * Note: This is NOT binary compatible with libmaxminddb's MMDB_s.
 * Applications must recompile. Most apps don't directly access fields.
 */
typedef struct MMDB_s {
    /* Internal matchy handle */
    matchy_t *_matchy_db;
    
    /* Public fields for compatibility (populated on open) */
    uint32_t flags;
    const char *filename;
    
    /* These fields exist for compatibility but may not be fully populated */
    ssize_t file_size;
} MMDB_s;

/* Entry pointer into data section */
typedef struct MMDB_entry_s {
    const MMDB_s *mmdb;
    matchy_entry_s _matchy_entry;
} MMDB_entry_s;

/* Lookup result */
typedef struct MMDB_lookup_result_s {
    bool found_entry;
    MMDB_entry_s entry;
    uint16_t netmask;
} MMDB_lookup_result_s;

/* Entry data (maps to matchy_entry_data_t) */
typedef struct MMDB_entry_data_s {
    bool has_data;
    uint32_t type;
    union {
        uint32_t pointer;
        const char *utf8_string;
        double double_value;
        const uint8_t *bytes;
        uint16_t uint16;
        uint32_t uint32;
        int32_t int32;
        uint64_t uint64;
        uint8_t uint128[16];
        bool boolean;
        float float_value;
    };
    uint32_t data_size;
    uint32_t offset;
} MMDB_entry_data_s;

/* Entry data list (linked list of entry data) */
typedef struct MMDB_entry_data_list_s {
    MMDB_entry_data_s entry_data;
    struct MMDB_entry_data_list_s *next;
    void *pool;  /* Memory pool (not used in matchy) */
} MMDB_entry_data_list_s;

/* Search node (for MMDB_read_node - rarely used) */
typedef struct MMDB_search_node_s {
    uint64_t left_record;
    uint64_t right_record;
    uint8_t left_record_type;
    uint8_t right_record_type;
    MMDB_entry_s left_record_entry;
    MMDB_entry_s right_record_entry;
} MMDB_search_node_s;

/* ========================================================================
 * API FUNCTIONS
 * ======================================================================== */

/* Open a MaxMind DB file
 * 
 * Parameters:
 *   filename: Path to .mmdb file
 *   flags: MMDB_MODE_MMAP (other flags ignored)
 *   mmdb: Pointer to MMDB_s struct (will be initialized)
 * 
 * Returns:
 *   MMDB_SUCCESS on success, error code on failure
 * 
 * Note: The mmdb struct should be zero-initialized or on stack.
 */
extern int MMDB_open(
    const char *filename,
    uint32_t flags,
    MMDB_s *mmdb
);

/* Lookup an IP address from string
 * 
 * Parameters:
 *   mmdb: Opened database handle
 *   ipstr: IP address as string (e.g., "8.8.8.8")
 *   gai_error: Pointer to store getaddrinfo error (may be NULL)
 *   mmdb_error: Pointer to store MMDB error (may be NULL)
 * 
 * Returns:
 *   Lookup result with found_entry=true if found
 */
extern MMDB_lookup_result_s MMDB_lookup_string(
    const MMDB_s *mmdb,
    const char *ipstr,
    int *gai_error,
    int *mmdb_error
);

/* Lookup an IP address from sockaddr
 * 
 * Parameters:
 *   mmdb: Opened database handle
 *   sockaddr: Socket address structure
 *   mmdb_error: Pointer to store error code (may be NULL)
 * 
 * Returns:
 *   Lookup result with found_entry=true if found
 */
extern MMDB_lookup_result_s MMDB_lookup_sockaddr(
    const MMDB_s *mmdb,
    const struct sockaddr *sockaddr,
    int *mmdb_error
);

/* Get value from entry using path (varargs version)
 * 
 * Parameters:
 *   start: Entry to navigate from
 *   entry_data: Output entry data
 *   ...: NULL-terminated path of string keys
 * 
 * Returns:
 *   MMDB_SUCCESS if found, error code otherwise
 * 
 * Example:
 *   MMDB_get_value(&result.entry, &data, "country", "iso_code", NULL);
 */
extern int MMDB_get_value(
    MMDB_entry_s *start,
    MMDB_entry_data_s *entry_data,
    ...
);

/* Get value from entry using path (va_list version) */
extern int MMDB_vget_value(
    MMDB_entry_s *start,
    MMDB_entry_data_s *entry_data,
    va_list va_path
);

/* Get value from entry using path (array version) */
extern int MMDB_aget_value(
    MMDB_entry_s *start,
    MMDB_entry_data_s *entry_data,
    const char *const *path
);

/* Get full entry data as linked list
 * 
 * This traverses the entire data structure and returns it as a
 * flattened linked list.
 * 
 * Parameters:
 *   start: Entry to traverse
 *   entry_data_list: Output list pointer
 * 
 * Returns:
 *   MMDB_SUCCESS on success
 * 
 * Note: Caller must free with MMDB_free_entry_data_list()
 */
extern int MMDB_get_entry_data_list(
    MMDB_entry_s *start,
    MMDB_entry_data_list_s **entry_data_list
);

/* Free entry data list */
extern void MMDB_free_entry_data_list(
    MMDB_entry_data_list_s *entry_data_list
);

/* Close database and free resources
 * 
 * Parameters:
 *   mmdb: Database handle to close
 * 
 * Note: After calling this, the mmdb struct should not be used.
 */
extern void MMDB_close(MMDB_s *mmdb);

/* Get library version string
 * 
 * Returns:
 *   Version string (e.g., "0.4.0-matchy")
 */
extern const char *MMDB_lib_version(void);

/* Convert error code to string
 * 
 * Parameters:
 *   error_code: MMDB error code
 * 
 * Returns:
 *   Human-readable error description
 */
extern const char *MMDB_strerror(int error_code);

/* ========================================================================
 * STUB FUNCTIONS (Rarely used, not implemented)
 * ======================================================================== */

/* Read a specific node from the search tree
 * 
 * This is a low-level function rarely used in applications.
 * Returns MMDB_INVALID_NODE_NUMBER_ERROR (not implemented).
 */
extern int MMDB_read_node(
    const MMDB_s *mmdb,
    uint32_t node_number,
    MMDB_search_node_s *node
);

/* Dump entry data list to file stream
 * 
 * This is a debugging function. Not implemented.
 * Returns MMDB_INVALID_DATA_ERROR (not implemented).
 */
extern int MMDB_dump_entry_data_list(
    FILE *stream,
    const MMDB_entry_data_list_s *entry_data_list,
    int indent
);

/* Get metadata as entry data list
 * 
 * Uncommon function. Not implemented.
 * Returns MMDB_INVALID_DATA_ERROR (not implemented).
 */
extern int MMDB_get_metadata_as_entry_data_list(
    const MMDB_s *mmdb,
    MMDB_entry_data_list_s **entry_data_list
);

#ifdef __cplusplus
}
#endif

#endif /* MAXMINDDB_COMPAT_H */
