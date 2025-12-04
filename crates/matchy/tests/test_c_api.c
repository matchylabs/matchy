// Test suite for matchy C API

#include "matchy/matchy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define TEMP_DB_PATH "C:\\Temp\\matchy_c_test.db"
#else
#define TEMP_DB_PATH "/tmp/matchy_c_test.db"
#endif

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
    const char* tmpfile = TEMP_DB_PATH;
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
    
    // Test 6: matchy_query_into (FFI-friendly variant)
    printf("\n--- Testing matchy_query_into API ---\n");
    
    matchy_t* db6 = matchy_open(tmpfile);
    if (db6 == NULL) {
        fprintf(stderr, "Failed to open database for query_into test\n");
        return 1;
    }
    
    // Test query_into with matching result
    matchy_result_t result_into;
    matchy_query_into(db6, "test_file.txt", &result_into);
    if (!result_into.found) {
        fprintf(stderr, "query_into did not find match\n");
        return 1;
    }
    printf("✓ query_into found match\n");
    matchy_free_result(&result_into);
    
    // Test query_into with non-matching query
    matchy_query_into(db6, "no_match.xyz", &result_into);
    if (result_into.found) {
        fprintf(stderr, "query_into incorrectly found match\n");
        return 1;
    }
    printf("✓ query_into correctly returned not found\n");
    
    // Test equivalence between query and query_into
    matchy_result_t result_a = matchy_query(db6, "test_file.txt");
    matchy_result_t result_b;
    matchy_query_into(db6, "test_file.txt", &result_b);
    
    if (result_a.found != result_b.found) {
        fprintf(stderr, "query and query_into returned different found values\n");
        return 1;
    }
    if (result_a.prefix_len != result_b.prefix_len) {
        fprintf(stderr, "query and query_into returned different prefix_len values\n");
        return 1;
    }
    printf("✓ query and query_into are equivalent\n");
    
    matchy_free_result(&result_a);
    matchy_free_result(&result_b);
    matchy_close(db6);
    
    // Test 7: Extractor API
    printf("\n--- Testing Extractor API ---\n");
    
    // Create extractor with all types
    matchy_extractor_t *extractor = matchy_extractor_create(MATCHY_EXTRACT_ALL);
    if (extractor == NULL) {
        fprintf(stderr, "Failed to create extractor\n");
        return 1;
    }
    printf("✓ Extractor created with MATCHY_EXTRACT_ALL\n");
    
    // Test extraction
    const char *test_text = "Check evil.com and 192.168.1.1 or user@example.com";
    matchy_matches_t matches;
    
    int extract_result = matchy_extractor_extract_chunk(
        extractor, 
        (const uint8_t *)test_text, 
        strlen(test_text), 
        &matches
    );
    
    if (extract_result != MATCHY_SUCCESS) {
        fprintf(stderr, "Extraction failed with code %d\n", extract_result);
        return 1;
    }
    printf("✓ Extraction succeeded\n");
    
    // Should find domain, IPv4, and email
    if (matches.count < 3) {
        fprintf(stderr, "Expected at least 3 matches, got %zu\n", matches.count);
        return 1;
    }
    printf("✓ Found %zu matches\n", matches.count);
    
    // Print all matches
    int found_domain = 0, found_ipv4 = 0, found_email = 0;
    for (size_t i = 0; i < matches.count; i++) {
        const char *type_name = matchy_item_type_name(matches.items[i].item_type);
        printf("  Match %zu: %s = \"%s\" (bytes %zu-%zu)\n", 
               i, type_name, matches.items[i].value,
               matches.items[i].start, matches.items[i].end);
        
        if (matches.items[i].item_type == MATCHY_ITEM_TYPE_DOMAIN) found_domain = 1;
        if (matches.items[i].item_type == MATCHY_ITEM_TYPE_IPV4) found_ipv4 = 1;
        if (matches.items[i].item_type == MATCHY_ITEM_TYPE_EMAIL) found_email = 1;
    }
    
    if (!found_domain || !found_ipv4 || !found_email) {
        fprintf(stderr, "Missing expected match types: domain=%d ipv4=%d email=%d\n",
                found_domain, found_ipv4, found_email);
        return 1;
    }
    printf("✓ Found all expected types (domain, IPv4, email)\n");
    
    matchy_matches_free(&matches);
    matchy_extractor_free(extractor);
    printf("✓ Extractor cleaned up\n");
    
    // Test selective extraction (domains only)
    printf("\n--- Testing selective extraction ---\n");
    
    matchy_extractor_t *domain_only = matchy_extractor_create(MATCHY_EXTRACT_DOMAINS);
    if (domain_only == NULL) {
        fprintf(stderr, "Failed to create domain-only extractor\n");
        return 1;
    }
    
    extract_result = matchy_extractor_extract_chunk(
        domain_only,
        (const uint8_t *)test_text,
        strlen(test_text),
        &matches
    );
    
    if (extract_result != MATCHY_SUCCESS) {
        fprintf(stderr, "Domain-only extraction failed\n");
        return 1;
    }
    
    // Should only find domains, not IPs or emails
    for (size_t i = 0; i < matches.count; i++) {
        if (matches.items[i].item_type != MATCHY_ITEM_TYPE_DOMAIN) {
            fprintf(stderr, "Found non-domain type %d in domain-only extraction\n",
                    matches.items[i].item_type);
            return 1;
        }
    }
    printf("✓ Domain-only extraction works (found %zu domains)\n", matches.count);
    
    matchy_matches_free(&matches);
    matchy_extractor_free(domain_only);
    
    // Test item_type_name for all types
    printf("\n--- Testing matchy_item_type_name ---\n");
    
    const char *name;
    name = matchy_item_type_name(MATCHY_ITEM_TYPE_DOMAIN);
    if (strcmp(name, "Domain") != 0) { fprintf(stderr, "Bad name for DOMAIN\n"); return 1; }
    
    name = matchy_item_type_name(MATCHY_ITEM_TYPE_EMAIL);
    if (strcmp(name, "Email") != 0) { fprintf(stderr, "Bad name for EMAIL\n"); return 1; }
    
    name = matchy_item_type_name(MATCHY_ITEM_TYPE_IPV4);
    if (strcmp(name, "IPv4") != 0) { fprintf(stderr, "Bad name for IPV4\n"); return 1; }
    
    name = matchy_item_type_name(MATCHY_ITEM_TYPE_IPV6);
    if (strcmp(name, "IPv6") != 0) { fprintf(stderr, "Bad name for IPV6\n"); return 1; }
    
    name = matchy_item_type_name(MATCHY_ITEM_TYPE_SHA256);
    if (strcmp(name, "SHA256") != 0) { fprintf(stderr, "Bad name for SHA256\n"); return 1; }
    
    name = matchy_item_type_name(MATCHY_ITEM_TYPE_BITCOIN);
    if (strcmp(name, "Bitcoin") != 0) { fprintf(stderr, "Bad name for BITCOIN\n"); return 1; }
    
    name = matchy_item_type_name(255);  // Invalid type
    if (strcmp(name, "Unknown") != 0) { fprintf(stderr, "Bad name for invalid type\n"); return 1; }
    
    printf("✓ All type names correct\n");
    
    printf("\n=== All C API tests passed! ===\n");
    return 0;
}
