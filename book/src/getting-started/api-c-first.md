# First Database with C

Let's build and query a [*database*][def-database] using the C API.

## Create a source file

Create `example.c`:

```c
#include "matchy.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Create a builder
    matchy_builder_t *builder = matchy_builder_new();
    if (!builder) {
        fprintf(stderr, "Failed to create builder\n");
        return 1;
    }
    
    // Add entries with JSON data
    int err = matchy_builder_add(builder, "192.0.2.1",
        "{\"threat_level\": \"high\", \"category\": \"malware\"}");
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add IP entry\n");
        matchy_builder_free(builder);
        return 1;
    }
    
    matchy_builder_add(builder, "10.0.0.0/8",
        "{\"network\": \"internal\"}");
    
    matchy_builder_add(builder, "*.evil.com",
        "{\"category\": \"phishing\"}");
    
    // Save to file
    err = matchy_builder_save(builder, "threats.mxy");
    if (err != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to save database\n");
        matchy_builder_free(builder);
        return 1;
    }
    printf("✅ Built database\n");
    matchy_builder_free(builder);
    
    // Open the database
    matchy_t *db = matchy_open("threats.mxy");
    if (!db) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }
    printf("✅ Loaded database\n");
    
    // Query an IP address
    matchy_result_t result = matchy_query(db, "192.0.2.1");
    if (result.found) {
        char *json = matchy_result_to_json(&result);
        printf("🔍 IP match: %s\n", json);
        matchy_free_string(json);
        matchy_free_result(&result);
    }
    
    // Query a pattern
    result = matchy_query(db, "phishing.evil.com");
    if (result.found) {
        char *json = matchy_result_to_json(&result);
        printf("🔍 Pattern match: %s\n", json);
        matchy_free_string(json);
        matchy_free_result(&result);
    }
    
    // Cleanup
    matchy_close(db);
    printf("✅ Done\n");
    
    return 0;
}
```

## Compile and run

```console
$ gcc -o example example.c -I/usr/local/include -L/usr/local/lib -lmatchy
$ ./example
✅ Built database
✅ Loaded database
🔍 IP match: {"threat_level":"high","category":"malware"}
🔍 Pattern match: {"category":"phishing"}
✅ Done
```

If you get "library not found" errors:

```console
$ export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH  # Linux
$ export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH  # macOS
```

## Understanding the code

### 1. Create a builder

```c
matchy_builder_t *builder = matchy_builder_new();
```

The builder is an opaque handle. Always check for `NULL` on creation.

### 2. Add entries

```c
matchy_builder_add(builder, "192.0.2.1",
    "{\"threat_level\": \"high\", \"category\": \"malware\"}");
```

The C API uses JSON strings for data. Matchy automatically detects whether the key
is an IP, CIDR, pattern, or exact string.

### 3. Save the database

```c
int err = matchy_builder_save(builder, "threats.mxy");
```

Returns `MATCHY_SUCCESS` (0) on success, or an error code otherwise.

### 4. Open and query

```c
matchy_t *db = matchy_open("threats.mxy");
matchy_result_t result = matchy_query(db, "192.0.2.1");
```

The database is memory-mapped for instant loading. Check `result.found` to see if
a match was found.

> **Note**: For FFI systems that have issues with return-by-value structs (like some
> Java JNA configurations on ARM64), use `matchy_query_into()` instead:
> ```c
> matchy_result_t result;
> matchy_query_into(db, "192.0.2.1", &result);
> ```
> Both functions are equivalent; `matchy_query_into()` writes to a pointer you provide.

### 5. Cleanup

```c
matchy_free_result(&result);
matchy_close(db);
matchy_builder_free(builder);
```

Always free resources when done. The C API uses manual memory management.

## Error handling

Check return values:

```c
int err = matchy_builder_add(builder, key, data);
if (err != MATCHY_SUCCESS) {
    const char *msg = matchy_error_message(err);
    fprintf(stderr, "Error: %s\n", msg);
}
```

Error codes:
- `MATCHY_SUCCESS` (0) - Operation succeeded
- `MATCHY_ERROR_INVALID_PARAM` - NULL pointer or invalid parameter
- `MATCHY_ERROR_FILE_NOT_FOUND` - File doesn't exist
- `MATCHY_ERROR_INVALID_FORMAT` - Corrupt or wrong format
- `MATCHY_ERROR_PARSE_FAILED` - JSON parsing failed
- `MATCHY_ERROR_UNKNOWN` - Other error

## Memory management

The C API follows these rules:

1. **Strings returned by Matchy must be freed**:
   ```c
   char *json = matchy_result_to_json(&result);
   // Use json...
   matchy_free_string(json);
   ```

2. **Results must be freed**:
   ```c
   matchy_result_t result = matchy_query(db, "key");
   // Use result...
   matchy_free_result(&result);
   ```

3. **Handles must be freed**:
   ```c
   matchy_builder_free(builder);
   matchy_close(db);
   ```

See [C Memory Management](../reference/c-memory.md) for complete details.

## Thread safety

- **Database handles** (`matchy_t*`) are thread-safe for concurrent queries
- **Builder handles** (`matchy_builder_t*`) are NOT thread-safe
- Don't share a builder across threads
- Multiple threads can safely query the same database

## Going further

* [C API Reference](../reference/c-api.md) - Complete C API documentation
* [C Memory Management](../reference/c-memory.md) - Memory rules and patterns
* [Matchy Guide](../guide/index.md) - Deeper dive into concepts

[def-database]: ../appendix/glossary.md#database '"database" (glossary entry)'
