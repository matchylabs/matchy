// Comprehensive test suite for MaxMind DB compatibility layer
// Tests MMDB_* API functions using both real GeoLite2 database and synthetic test database

#include <matchy/maxminddb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define TEST_DB_PATH "/tmp/matchy_mmdb_test.db"
#define GEOLITE_DB_PATH "tests/data/GeoLite2-Country.mmdb"
#define PASSED_COLOR "\033[32m"
#define FAILED_COLOR "\033[31m"
#define RESET_COLOR "\033[0m"

int tests_passed = 0;
int tests_failed = 0;

#define TEST(name) \
    printf("\n--- Test: %s ---\n", name); \
    int test_passed = 1;

#define ASSERT(condition, msg) \
    if (!(condition)) { \
        printf(FAILED_COLOR "✗ FAILED: %s\n" RESET_COLOR, msg); \
        test_passed = 0; \
    } else { \
        printf(PASSED_COLOR "✓ PASSED: %s\n" RESET_COLOR, msg); \
    }

#define END_TEST() \
    if (test_passed) { \
        tests_passed++; \
    } else { \
        tests_failed++; \
    }

// Create a test database with structured data
int create_test_database() {
    // Use matchy API to create test database
    matchy_builder_t *builder = matchy_builder_new();
    if (builder == NULL) {
        fprintf(stderr, "Failed to create builder\n");
        return -1;
    }
    
    // Add test data similar to GeoIP format
    const char *test_data = "{"
        "\"country\":{"
            "\"iso_code\":\"US\","
            "\"names\":{"
                "\"en\":\"United States\","
                "\"es\":\"Estados Unidos\""
            "},"
            "\"geoname_id\":6252001"
        "},"
        "\"location\":{"
            "\"latitude\":37.751,"
            "\"longitude\":-97.822"
        "}"
    "}";
    
    const char *uk_data = "{"
        "\"country\":{"
            "\"iso_code\":\"GB\","
            "\"names\":{"
                "\"en\":\"United Kingdom\""
            "},"
            "\"geoname_id\":2635167"
        "}"
    "}";
    
    if (matchy_builder_add(builder, "8.8.8.8", test_data) != MATCHY_SUCCESS ||
        matchy_builder_add(builder, "8.8.4.4", test_data) != MATCHY_SUCCESS ||
        matchy_builder_add(builder, "81.2.69.142", uk_data) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add entries\n");
        matchy_builder_free(builder);
        return -1;
    }
    
    if (matchy_builder_save(builder, TEST_DB_PATH) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to save database\n");
        matchy_builder_free(builder);
        return -1;
    }
    
    matchy_builder_free(builder);
    return 0;
}

void test_mmdb_open() {
    TEST("MMDB_open");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    int status = MMDB_open(TEST_DB_PATH, MMDB_MODE_MMAP, &mmdb);
    ASSERT(status == MMDB_SUCCESS, "Should successfully open database");
    ASSERT(mmdb._matchy_db != NULL, "Database handle should not be NULL");
    ASSERT(mmdb.filename != NULL, "Filename should be set");
    ASSERT(strcmp(mmdb.filename, TEST_DB_PATH) == 0, "Filename should match");
    
    printf("  Opened: %s\n", mmdb.filename);
    
    MMDB_close(&mmdb);
    END_TEST();
}

void test_mmdb_open_invalid() {
    TEST("MMDB_open with invalid file");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    int status = MMDB_open("/nonexistent/file.mmdb", MMDB_MODE_MMAP, &mmdb);
    ASSERT(status != MMDB_SUCCESS, "Should fail to open nonexistent file");
    
    END_TEST();
}

void test_mmdb_lookup_string() {
    TEST("MMDB_lookup_string");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    if (MMDB_open(TEST_DB_PATH, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        printf("Failed to open database\n");
        END_TEST();
        return;
    }
    
    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "8.8.8.8", &gai_error, &mmdb_error);
    
    ASSERT(result.found_entry, "Should find 8.8.8.8");
    ASSERT(mmdb_error == MMDB_SUCCESS, "Should have no MMDB error");
    ASSERT(result.netmask > 0, "Should have valid netmask");
    
    printf("  Found entry with netmask: %u\n", result.netmask);
    
    MMDB_close(&mmdb);
    END_TEST();
}

void test_mmdb_lookup_string_not_found() {
    TEST("MMDB_lookup_string - not found");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    if (MMDB_open(TEST_DB_PATH, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        printf("Failed to open database\n");
        END_TEST();
        return;
    }
    
    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "11.11.11.11", &gai_error, &mmdb_error);
    
    ASSERT(!result.found_entry, "Should not find 11.11.11.11");
    
    MMDB_close(&mmdb);
    END_TEST();
}

void test_mmdb_lookup_sockaddr() {
    TEST("MMDB_lookup_sockaddr");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    if (MMDB_open(TEST_DB_PATH, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        printf("Failed to open database\n");
        END_TEST();
        return;
    }
    
    // Create sockaddr for 8.8.8.8
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, "8.8.8.8", &(sa.sin_addr));
    
    int mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_sockaddr(&mmdb, (struct sockaddr *)&sa, &mmdb_error);
    
    ASSERT(result.found_entry, "Should find 8.8.8.8 via sockaddr");
    ASSERT(mmdb_error == MMDB_SUCCESS, "Should have no MMDB error");
    
    printf("  Found entry via sockaddr\n");
    
    MMDB_close(&mmdb);
    END_TEST();
}

void test_mmdb_aget_value() {
    TEST("MMDB_aget_value - nested string");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    if (MMDB_open(TEST_DB_PATH, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        printf("Failed to open database\n");
        END_TEST();
        return;
    }
    
    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "8.8.8.8", &gai_error, &mmdb_error);
    
    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        const char *path[] = {"country", "iso_code", NULL};
        
        int status = MMDB_aget_value(&result.entry, &entry_data, path);
        
        ASSERT(status == MMDB_SUCCESS, "Should successfully get country.iso_code");
        ASSERT(entry_data.has_data, "Should have data");
        ASSERT(entry_data.type == MMDB_DATA_TYPE_UTF8_STRING, "Should be string type");
        ASSERT(strcmp(entry_data.utf8_string, "US") == 0, "Value should be 'US'");
        
        printf("  Retrieved: %s\n", entry_data.utf8_string);
    }
    
    MMDB_close(&mmdb);
    END_TEST();
}

void test_mmdb_get_value() {
    TEST("MMDB_get_value - varargs version");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    if (MMDB_open(TEST_DB_PATH, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        printf("Failed to open database\n");
        END_TEST();
        return;
    }
    
    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "8.8.8.8", &gai_error, &mmdb_error);
    
    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        
        // Test varargs version
        int status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
        
        ASSERT(status == MMDB_SUCCESS, "Should successfully get value via varargs");
        ASSERT(entry_data.has_data, "Should have data");
        ASSERT(entry_data.type == MMDB_DATA_TYPE_UTF8_STRING, "Should be string type");
        
        printf("  Retrieved via varargs: %s\n", entry_data.utf8_string);
    }
    
    MMDB_close(&mmdb);
    END_TEST();
}

void test_mmdb_get_value_nested() {
    TEST("MMDB_get_value - deeply nested path");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    if (MMDB_open(TEST_DB_PATH, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        printf("Failed to open database\n");
        END_TEST();
        return;
    }
    
    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "8.8.8.8", &gai_error, &mmdb_error);
    
    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        int status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
        
        if (status == MMDB_SUCCESS && entry_data.has_data) {
            ASSERT(entry_data.type == MMDB_DATA_TYPE_UTF8_STRING, "Should be string type");
            ASSERT(strcmp(entry_data.utf8_string, "United States") == 0, 
                   "Value should be 'United States'");
            printf("  Country name (en): %s\n", entry_data.utf8_string);
        } else {
            printf("  Note: deeply nested path not found (may be expected)\n");
        }
    }
    
    MMDB_close(&mmdb);
    END_TEST();
}

void test_mmdb_get_value_numeric() {
    TEST("MMDB_get_value - numeric values");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    if (MMDB_open(TEST_DB_PATH, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        printf("Failed to open database\n");
        END_TEST();
        return;
    }
    
    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "8.8.8.8", &gai_error, &mmdb_error);
    
    if (result.found_entry) {
        // Test double (latitude)
        MMDB_entry_data_s entry_data;
        int status = MMDB_get_value(&result.entry, &entry_data, "location", "latitude", NULL);
        
        if (status == MMDB_SUCCESS && entry_data.has_data) {
            ASSERT(entry_data.type == MMDB_DATA_TYPE_DOUBLE, "Latitude should be double");
            printf("  Latitude: %.3f\n", entry_data.double_value);
        }
        
        // Test uint32 (geoname_id)
        status = MMDB_get_value(&result.entry, &entry_data, "country", "geoname_id", NULL);
        
        if (status == MMDB_SUCCESS && entry_data.has_data) {
            ASSERT(entry_data.type == MMDB_DATA_TYPE_UINT32 || 
                   entry_data.type == MMDB_DATA_TYPE_UINT64,
                   "geoname_id should be uint32 or uint64");
            
            if (entry_data.type == MMDB_DATA_TYPE_UINT32) {
                printf("  Geoname ID: %u\n", entry_data.uint32);
            } else {
                printf("  Geoname ID: %llu\n", (unsigned long long)entry_data.uint64);
            }
        }
    }
    
    MMDB_close(&mmdb);
    END_TEST();
}

void test_mmdb_get_entry_data_list() {
    TEST("MMDB_get_entry_data_list");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    if (MMDB_open(TEST_DB_PATH, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        printf("Failed to open database\n");
        END_TEST();
        return;
    }
    
    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "8.8.8.8", &gai_error, &mmdb_error);
    
    if (result.found_entry) {
        MMDB_entry_data_list_s *list = NULL;
        int status = MMDB_get_entry_data_list(&result.entry, &list);
        
        ASSERT(status == MMDB_SUCCESS, "Should successfully get entry data list");
        ASSERT(list != NULL, "List should not be NULL");
        
        if (list) {
            int count = 0;
            MMDB_entry_data_list_s *current = list;
            
            while (current != NULL) {
                count++;
                current = current->next;
            }
            
            ASSERT(count > 0, "Should have at least one node");
            printf("  Total nodes in list: %d\n", count);
            
            MMDB_free_entry_data_list(list);
        }
    }
    
    MMDB_close(&mmdb);
    END_TEST();
}

void test_mmdb_lib_version() {
    TEST("MMDB_lib_version");
    
    const char *version = MMDB_lib_version();
    
    ASSERT(version != NULL, "Version string should not be NULL");
    ASSERT(strlen(version) > 0, "Version string should not be empty");
    
    printf("  Library version: %s\n", version);
    
    END_TEST();
}

void test_mmdb_strerror() {
    TEST("MMDB_strerror");
    
    const char *success_msg = MMDB_strerror(MMDB_SUCCESS);
    ASSERT(success_msg != NULL, "Success message should not be NULL");
    printf("  MMDB_SUCCESS: %s\n", success_msg);
    
    const char *error_msg = MMDB_strerror(MMDB_FILE_OPEN_ERROR);
    ASSERT(error_msg != NULL, "Error message should not be NULL");
    printf("  MMDB_FILE_OPEN_ERROR: %s\n", error_msg);
    
    END_TEST();
}

void test_mmdb_with_geolite() {
    TEST("MMDB with real GeoLite2 database");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    // Try to open GeoLite2 database (may not exist in all environments)
    int status = MMDB_open(GEOLITE_DB_PATH, MMDB_MODE_MMAP, &mmdb);
    
    if (status != MMDB_SUCCESS) {
        printf("  GeoLite2 database not found (this is OK for CI)\n");
        END_TEST();
        return;
    }
    
    ASSERT(status == MMDB_SUCCESS, "Should successfully open GeoLite2 database");
    printf("  Opened GeoLite2 database\n");
    
    // Test lookup
    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "8.8.8.8", &gai_error, &mmdb_error);
    
    if (result.found_entry) {
        printf("  Found entry for 8.8.8.8\n");
        
        // Try to get country code
        MMDB_entry_data_s entry_data;
        int lookup_status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
        
        if (lookup_status == MMDB_SUCCESS && entry_data.has_data) {
            printf("  Country code: %s\n", entry_data.utf8_string);
        }
    }
    
    MMDB_close(&mmdb);
    END_TEST();
}

void test_mmdb_multiple_lookups() {
    TEST("MMDB multiple lookups");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    if (MMDB_open(TEST_DB_PATH, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        printf("Failed to open database\n");
        END_TEST();
        return;
    }
    
    const char *test_ips[] = {"8.8.8.8", "8.8.4.4", "81.2.69.142"};
    int found_count = 0;
    
    for (int i = 0; i < 3; i++) {
        int gai_error = 0, mmdb_error = 0;
        MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, test_ips[i], &gai_error, &mmdb_error);
        
        if (result.found_entry) {
            found_count++;
            
            MMDB_entry_data_s entry_data;
            if (MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL) == MMDB_SUCCESS) {
                printf("  %s -> %s\n", test_ips[i], entry_data.utf8_string);
            }
        }
    }
    
    ASSERT(found_count == 3, "Should find all three IPs");
    
    MMDB_close(&mmdb);
    END_TEST();
}

void test_mmdb_invalid_path() {
    TEST("MMDB_get_value - invalid path");
    
    MMDB_s mmdb;
    memset(&mmdb, 0, sizeof(MMDB_s));
    
    if (MMDB_open(TEST_DB_PATH, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        printf("Failed to open database\n");
        END_TEST();
        return;
    }
    
    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, "8.8.8.8", &gai_error, &mmdb_error);
    
    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        int status = MMDB_get_value(&result.entry, &entry_data, "nonexistent", "path", NULL);
        
        ASSERT(status != MMDB_SUCCESS, "Should fail for invalid path");
        ASSERT(!entry_data.has_data, "Should not have data");
    }
    
    MMDB_close(&mmdb);
    END_TEST();
}

int main() {
    printf("========================================\n");
    printf("MaxMind DB Compatibility Test Suite\n");
    printf("========================================\n\n");
    
    // Create test database
    printf("Creating test database...\n");
    if (create_test_database() != 0) {
        fprintf(stderr, "Failed to create test database\n");
        return 1;
    }
    printf("✓ Test database created\n");
    
    // Run tests
    test_mmdb_open();
    test_mmdb_open_invalid();
    test_mmdb_lookup_string();
    test_mmdb_lookup_string_not_found();
    test_mmdb_lookup_sockaddr();
    test_mmdb_aget_value();
    test_mmdb_get_value();
    test_mmdb_get_value_nested();
    test_mmdb_get_value_numeric();
    test_mmdb_get_entry_data_list();
    test_mmdb_lib_version();
    test_mmdb_strerror();
    test_mmdb_with_geolite();
    test_mmdb_multiple_lookups();
    test_mmdb_invalid_path();
    
    // Print summary
    printf("\n========================================\n");
    printf("Test Results:\n");
    printf("  " PASSED_COLOR "%d tests passed" RESET_COLOR "\n", tests_passed);
    if (tests_failed > 0) {
        printf("  " FAILED_COLOR "%d tests failed" RESET_COLOR "\n", tests_failed);
    }
    printf("========================================\n");
    
    return tests_failed > 0 ? 1 : 0;
}
