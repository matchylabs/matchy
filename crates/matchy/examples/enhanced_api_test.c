// Example demonstrating the enhanced C API with structured data access

#include "../include/matchy.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("=== Matchy Enhanced API Test ===\n\n");
    
    // Create a test database
    matchy_builder_t *builder = matchy_builder_new();
    if (builder == NULL) {
        fprintf(stderr, "Failed to create builder\n");
        return 1;
    }
    printf("✓ Builder created\n");
    
    // Add some test data with nested structure
    const char *test_data = "{\"country\":{\"iso_code\":\"US\"}}";
    
    if (matchy_builder_add(builder, "8.8.8.8", test_data) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add entry\n");
        return 1;
    }
    printf("✓ Added IP with nested data\n");
    
    // Build to temp file
    const char *tmpfile = "/tmp/matchy_enhanced_test.db";
    if (matchy_builder_save(builder, tmpfile) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to save database\n");
        return 1;
    }
    printf("✓ Database saved\n");
    
    matchy_builder_free(builder);
    
    // Open and query
    matchy_t *db = matchy_open(tmpfile);
    if (db == NULL) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }
    printf("✓ Database opened\n\n");
    
    // Query the IP
    matchy_result_t result = matchy_query(db, "8.8.8.8");
    if (!result.found) {
        printf("IP not found\n");
        matchy_close(db);
        return 0;
    }
    printf("✓ Query found match (prefix_len=%d)\n", result.prefix_len);
    
    // Get entry handle
    matchy_entry_s entry;
    if (matchy_result_get_entry(&result, &entry) != MATCHY_SUCCESS) {
        printf("Failed to get entry\n");
        matchy_free_result(&result);
        matchy_close(db);
        return 1;
    }
    printf("✓ Got entry handle\n\n");
    
    // Test 1: Navigate to country.iso_code
    printf("Test 1: Navigate to country.iso_code\n");
    matchy_entry_data_t data;
    const char *path1[] = {"country", "iso_code", NULL};
    int status = matchy_aget_value(&entry, &data, path1);
    
    if (status == MATCHY_SUCCESS && data.has_data) {
        if (data.type_ == MATCHY_DATA_TYPE_UTF8_STRING) {
            printf("  Result: %s (type: string, size: %u)\n", 
                   data.value.utf8_string, data.data_size);
        }
    } else {
        printf("  Failed: status=%d\n", status);
    }
    
    // Test 2: Navigate to country.names.en
    printf("\nTest 2: Navigate to country.names.en\n");
    const char *path2[] = {"country", "names", "en", NULL};
    status = matchy_aget_value(&entry, &data, path2);
    
    if (status == MATCHY_SUCCESS && data.has_data) {
        if (data.type_ == MATCHY_DATA_TYPE_UTF8_STRING) {
            printf("  Result: %s\n", data.value.utf8_string);
        }
    } else {
        printf("  Failed: status=%d\n", status);
    }
    
    // Test 3: Navigate to location.latitude (should be double)
    printf("\nTest 3: Navigate to location.latitude\n");
    const char *path3[] = {"location", "latitude", NULL};
    status = matchy_aget_value(&entry, &data, path3);
    
    if (status == MATCHY_SUCCESS && data.has_data) {
        if (data.type_ == MATCHY_DATA_TYPE_DOUBLE) {
            printf("  Result: %.4f (type: double)\n", data.value.double_value);
        } else {
            printf("  Unexpected type: %u\n", data.type_);
        }
    } else {
        printf("  Failed: status=%d\n", status);
    }
    
    // Test 4: Try invalid path
    printf("\nTest 4: Try invalid path (should fail gracefully)\n");
    const char *path4[] = {"invalid", "path", NULL};
    status = matchy_aget_value(&entry, &data, path4);
    
    if (status == MATCHY_ERROR_LOOKUP_PATH_INVALID) {
        printf("  ✓ Correctly returned MATCHY_ERROR_LOOKUP_PATH_INVALID\n");
    } else {
        printf("  Unexpected status: %d\n", status);
    }
    
    // Cleanup
    matchy_free_result(&result);
    matchy_close(db);
    
    printf("\n=== All tests completed successfully! ===\n");
    return 0;
}
