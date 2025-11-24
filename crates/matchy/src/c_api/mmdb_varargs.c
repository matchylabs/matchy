/* MaxMind DB varargs wrapper
 *
 * Rust can't implement varargs functions, so we provide C wrappers
 * that collect varargs and call the array-based versions.
 */

#include <matchy/maxminddb.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

/* Maximum path depth for MMDB_get_value */
#define MAX_PATH_DEPTH 32

/* MMDB_get_value - varargs version
 *
 * Collects varargs into array and calls MMDB_aget_value
 */
int MMDB_get_value(MMDB_entry_s *start, MMDB_entry_data_s *entry_data, ...) {
    va_list args;
    const char *path[MAX_PATH_DEPTH + 1];
    size_t count = 0;
    
    /* Collect varargs into array */
    va_start(args, entry_data);
    while (count < MAX_PATH_DEPTH) {
        const char *arg = va_arg(args, const char *);
        if (arg == NULL) {
            break;
        }
        path[count++] = arg;
    }
    va_end(args);
    
    /* NULL-terminate */
    path[count] = NULL;
    
    /* Call array version */
    return MMDB_aget_value(start, entry_data, path);
}

/* MMDB_vget_value - va_list version
 *
 * Collects va_list into array and calls MMDB_aget_value
 */
int MMDB_vget_value(MMDB_entry_s *start, MMDB_entry_data_s *entry_data, va_list va_path) {
    const char *path[MAX_PATH_DEPTH + 1];
    size_t count = 0;
    
    /* Copy va_list and collect into array */
    va_list args_copy;
    va_copy(args_copy, va_path);
    
    while (count < MAX_PATH_DEPTH) {
        const char *arg = va_arg(args_copy, const char *);
        if (arg == NULL) {
            break;
        }
        path[count++] = arg;
    }
    va_end(args_copy);
    
    /* NULL-terminate */
    path[count] = NULL;
    
    /* Call array version */
    return MMDB_aget_value(start, entry_data, path);
}
