// Test suite for matchy C API

#include "matchy/matchy.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("=== Matchy C API Tests ===\n\n");
    
    // Create builder
    matchy_builder_t* builder = matchy_builder_new();
    if (builder == NULL) {
        fprintf(stderr, "Builder creation failed\n");
        return 1;
    }
    printf("✓ Builder created\n");
    
    // Add patterns with simple data
    if (matchy_builder_add(builder, "*.txt", "{}") != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add pattern\n");
        return 1;
    }
    printf("✓ Pattern 1 added\n");
    
    if (matchy_builder_add(builder, "*.log", "{}") != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add pattern 2\n");
        return 1;
    }
    printf("✓ Pattern 2 added\n");
    
    if (matchy_builder_add(builder, "test_*", "{}") != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add pattern 3\n");
        return 1;
    }
    printf("✓ Pattern 3 added\n");
    
    // Build to temp file
    const char* tmpfile = "/tmp/matchy_c_test.db";
    if (matchy_builder_save(builder, tmpfile) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to save\n");
        return 1;
    }
    printf("✓ Database saved\n");
    
    matchy_builder_free(builder);
    
    // Open and test
    matchy_t* db = matchy_open(tmpfile);
    if (db == NULL) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }
    printf("✓ Database opened\n");
    
    // Check pattern count
    size_t count = matchy_pattern_count(db);
    printf("✓ Pattern count: %zu\n", count);
    if (count != 3) {
        fprintf(stderr, "Wrong pattern count: expected 3, got %zu\n", count);
        return 1;
    }
    
    // Test matching
    matchy_result_t result = matchy_query(db, "test_file.txt");
    if (!result.found) {
        fprintf(stderr, "No match found\n");
        return 1;
    }
    printf("✓ Query found match\n");
    
    // Free the result
    matchy_free_result(&result);
    
    matchy_close(db);
    
    // Test new open_with_options API
    printf("\n--- Testing open_with_options API ---\n");
    
    // Test 1: Open with default options
    matchy_open_options_t opts;
    matchy_init_open_options(&opts);
    
    matchy_t* db2 = matchy_open_with_options(tmpfile, &opts);
    if (db2 == NULL) {
        fprintf(stderr, "Failed to open with default options\n");
        return 1;
    }
    printf("✓ Opened with default options (cache: %u)\n", 
           opts.cache_capacity);
    
    // Verify it works
    result = matchy_query(db2, "test_file.txt");
    if (!result.found) {
        fprintf(stderr, "Query failed with default options\n");
        return 1;
    }
    matchy_free_result(&result);
    matchy_close(db2);
    printf("✓ Query works with default options\n");
    
    // Test 2: Open with cache disabled
    matchy_init_open_options(&opts);
    opts.cache_capacity = 0;  // Disable cache
    
    matchy_t* db3 = matchy_open_with_options(tmpfile, &opts);
    if (db3 == NULL) {
        fprintf(stderr, "Failed to open with cache disabled\n");
        return 1;
    }
    printf("✓ Opened with cache disabled\n");
    
    // Verify it still works
    result = matchy_query(db3, "test_file.txt");
    if (!result.found) {
        fprintf(stderr, "Query failed with cache disabled\n");
        return 1;
    }
    matchy_free_result(&result);
    matchy_close(db3);
    printf("✓ Query works with cache disabled\n");
    
    // Test 3: Open with custom cache size
    matchy_init_open_options(&opts);
    opts.cache_capacity = 100;  // Small cache
    
    matchy_t* db4 = matchy_open_with_options(tmpfile, &opts);
    if (db4 == NULL) {
        fprintf(stderr, "Failed to open with custom cache\n");
        return 1;
    }
    printf("✓ Opened with custom cache size (100)\n");
    
    // Test multiple queries to potentially hit cache
    for (int i = 0; i < 5; i++) {
        result = matchy_query(db4, "test_file.txt");
        if (!result.found) {
            fprintf(stderr, "Query %d failed\n", i);
            return 1;
        }
        matchy_free_result(&result);
    }
    matchy_close(db4);
    printf("✓ Multiple queries work with custom cache\n");
    
    // Test 4: Open with auto-reload disabled (explicit)
    matchy_init_open_options(&opts);
    opts.auto_reload = 0;  // Explicit disable (default is false anyway)
    opts.cache_capacity = 1000;
    
    matchy_t* db5 = matchy_open_with_options(tmpfile, &opts);
    if (db5 == NULL) {
        fprintf(stderr, "Failed to open with auto-reload disabled\n");
        return 1;
    }
    printf("✓ Opened with auto-reload disabled\n");
    
    result = matchy_query(db5, "test_file.txt");
    if (!result.found) {
        fprintf(stderr, "Query failed with auto-reload disabled\n");
        return 1;
    }
    matchy_free_result(&result);
    matchy_close(db5);
    printf("✓ Query works with auto-reload disabled\n");
    
    // Test 5: NULL pointer checks
    printf("\n--- Testing error handling ---\n");
    
    // NULL options should fail gracefully
    matchy_t* db_null = matchy_open_with_options(tmpfile, NULL);
    if (db_null != NULL) {
        fprintf(stderr, "Should have failed with NULL options\n");
        matchy_close(db_null);
        return 1;
    }
    printf("✓ NULL options rejected\n");
    
    // NULL path should fail
    matchy_init_open_options(&opts);
    db_null = matchy_open_with_options(NULL, &opts);
    if (db_null != NULL) {
        fprintf(stderr, "Should have failed with NULL path\n");
        matchy_close(db_null);
        return 1;
    }
    printf("✓ NULL path rejected\n");
    
    printf("\n=== All C API tests passed! ===\n");
    return 0;
}
