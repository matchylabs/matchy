// Comprehensive test suite for matchy C API extensions
// Tests the enhanced structured data API including matchy_result_get_entry,
// matchy_aget_value, matchy_get_entry_data_list, and matchy_result_to_json

#include "../include/matchy/matchy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef _WIN32
#define TEST_DB_PATH "C:\\Temp\\matchy_extensions_test.db"
#else
#define TEST_DB_PATH "/tmp/matchy_extensions_test.db"
#endif
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

// Create a test database with various data types
int create_test_database() {
    matchy_builder_t *builder = matchy_builder_new();
    if (builder == NULL) {
        fprintf(stderr, "Failed to create builder\n");
        return -1;
    }
    
    // IP with nested map structure (like GeoIP)
    const char *complex_data = "{\"country\":{\"iso_code\":\"US\",\"name\":\"United States\",\"geoname_id\":6252001},\"location\":{\"latitude\":37.751,\"longitude\":-97.822,\"accuracy_radius\":1000},\"registered_country\":{\"iso_code\":\"US\"}}";
    
    // Simple string data
    const char *simple_data = "{\"value\":\"simple_string\"}";
    
    // Array data
    const char *array_data = "{\"tags\":[\"prod\",\"web\",\"api\"]}";
    
    // Boolean data
    const char *bool_data = "{\"is_vpn\":true,\"is_proxy\":false}";
    
    // Numeric types
    const char *numeric_data = "{\"uint16_val\":65535,\"uint32_val\":4294967295,\"int32_val\":-2147483648,\"float_val\":3.14159,\"double_val\":2.718281828459045}";
    
    // Add test entries
    int status;
    if ((status = matchy_builder_add(builder, "8.8.8.8", complex_data)) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add 8.8.8.8: error %d\n", status);
        matchy_builder_free(builder);
        return -1;
    }
    if ((status = matchy_builder_add(builder, "1.1.1.1", simple_data)) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add 1.1.1.1: error %d\n", status);
        matchy_builder_free(builder);
        return -1;
    }
    if ((status = matchy_builder_add(builder, "9.9.9.9", array_data)) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add 9.9.9.9: error %d\n", status);
        matchy_builder_free(builder);
        return -1;
    }
    if ((status = matchy_builder_add(builder, "10.0.0.1", bool_data)) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add 10.0.0.1: error %d\n", status);
        matchy_builder_free(builder);
        return -1;
    }
    if ((status = matchy_builder_add(builder, "192.168.1.1", numeric_data)) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to add 192.168.1.1: error %d\n", status);
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

void test_result_get_entry(matchy_t *db) {
    TEST("matchy_result_get_entry");
    
    matchy_result_t result = matchy_query(db, "8.8.8.8");
    ASSERT(result.found, "Query should find 8.8.8.8");
    
    if (result.found) {
        matchy_entry_s entry;
        int status = matchy_result_get_entry(&result, &entry);
        ASSERT(status == MATCHY_SUCCESS, "Should successfully get entry");
        ASSERT(entry.db != NULL, "Entry should have database reference");
    }
    
    matchy_free_result(&result);
    END_TEST();
}

void test_result_get_entry_not_found(matchy_t *db) {
    TEST("matchy_result_get_entry with not found result");
    
    matchy_result_t result = matchy_query(db, "11.11.11.11");
    ASSERT(!result.found, "Query should not find 11.11.11.11");
    
    matchy_entry_s entry;
    int status = matchy_result_get_entry(&result, &entry);
    ASSERT(status == MATCHY_ERROR_NO_DATA, "Should return MATCHY_ERROR_NO_DATA for not found");
    
    matchy_free_result(&result);
    END_TEST();
}

void test_aget_value_nested_string(matchy_t *db) {
    TEST("matchy_aget_value - nested string");
    
    matchy_result_t result = matchy_query(db, "8.8.8.8");
    ASSERT(result.found, "Query should find 8.8.8.8");
    
    if (result.found) {
        matchy_entry_s entry;
        matchy_result_get_entry(&result, &entry);
        
        matchy_entry_data_t data;
        const char *path[] = {"country", "iso_code", NULL};
        int status = matchy_aget_value(&entry, &data, path);
        
        ASSERT(status == MATCHY_SUCCESS, "Should successfully get country.iso_code");
        ASSERT(data.has_data, "Should have data");
        ASSERT(data.type_ == MATCHY_DATA_TYPE_UTF8_STRING, "Should be string type");
        ASSERT(strcmp(data.value.utf8_string, "US") == 0, "Value should be 'US'");
        ASSERT(data.data_size == 2, "String size should be 2");
        
        printf("  Retrieved: %s (size=%u)\n", data.value.utf8_string, data.data_size);
    }
    
    matchy_free_result(&result);
    END_TEST();
}

void test_aget_value_double(matchy_t *db) {
    TEST("matchy_aget_value - double value");
    
    matchy_result_t result = matchy_query(db, "8.8.8.8");
    if (result.found) {
        matchy_entry_s entry;
        matchy_result_get_entry(&result, &entry);
        
        matchy_entry_data_t data;
        const char *path[] = {"location", "latitude", NULL};
        int status = matchy_aget_value(&entry, &data, path);
        
        ASSERT(status == MATCHY_SUCCESS, "Should successfully get location.latitude");
        ASSERT(data.has_data, "Should have data");
        ASSERT(data.type_ == MATCHY_DATA_TYPE_DOUBLE, "Should be double type");
        
        // Compare with some tolerance for floating point
        double expected = 37.751;
        double diff = data.value.double_value - expected;
        if (diff < 0) diff = -diff;
        ASSERT(diff < 0.001, "Latitude value should be approximately 37.751");
        
        printf("  Retrieved: %.3f\n", data.value.double_value);
    }
    
    matchy_free_result(&result);
    END_TEST();
}

void test_aget_value_uint32(matchy_t *db) {
    TEST("matchy_aget_value - uint32 value");
    
    matchy_result_t result = matchy_query(db, "8.8.8.8");
    if (result.found) {
        matchy_entry_s entry;
        matchy_result_get_entry(&result, &entry);
        
        matchy_entry_data_t data;
        const char *path[] = {"country", "geoname_id", NULL};
        int status = matchy_aget_value(&entry, &data, path);
        
        ASSERT(status == MATCHY_SUCCESS, "Should successfully get country.geoname_id");
        ASSERT(data.has_data, "Should have data");
        
        // JSON numbers are parsed as Double by default with untagged serde
        if (data.type_ == MATCHY_DATA_TYPE_DOUBLE) {
            double val = data.value.double_value;
            ASSERT(val > 6252000 && val < 6252002, "Value should be approximately 6252001");
            printf("  Retrieved: %.0f (as double)\n", val);
        } else if (data.type_ == MATCHY_DATA_TYPE_UINT32) {
            ASSERT(data.value.uint32 == 6252001, "Value should be 6252001");
            printf("  Retrieved: %u\n", data.value.uint32);
        } else if (data.type_ == MATCHY_DATA_TYPE_UINT64) {
            ASSERT(data.value.uint64 == 6252001, "Value should be 6252001");
            printf("  Retrieved: %llu\n", data.value.uint64);
        } else {
            printf("  Actual type: %u\n", data.type_);
            ASSERT(0, "Unexpected type for geoname_id");
        }
    }
    
    matchy_free_result(&result);
    END_TEST();
}

void test_aget_value_invalid_path(matchy_t *db) {
    TEST("matchy_aget_value - invalid path");
    
    matchy_result_t result = matchy_query(db, "8.8.8.8");
    if (result.found) {
        matchy_entry_s entry;
        matchy_result_get_entry(&result, &entry);
        
        matchy_entry_data_t data;
        const char *path[] = {"nonexistent", "path", NULL};
        int status = matchy_aget_value(&entry, &data, path);
        
        ASSERT(status == MATCHY_ERROR_LOOKUP_PATH_INVALID, 
               "Should return MATCHY_ERROR_LOOKUP_PATH_INVALID for invalid path");
        ASSERT(!data.has_data, "Should not have data");
    }
    
    matchy_free_result(&result);
    END_TEST();
}

void test_aget_value_boolean(matchy_t *db) {
    TEST("matchy_aget_value - boolean values");
    
    matchy_result_t result = matchy_query(db, "10.0.0.1");
    if (result.found) {
        matchy_entry_s entry;
        matchy_result_get_entry(&result, &entry);
        
        // Test true value
        matchy_entry_data_t data;
        const char *path_true[] = {"is_vpn", NULL};
        int status = matchy_aget_value(&entry, &data, path_true);
        
        ASSERT(status == MATCHY_SUCCESS, "Should get is_vpn");
        ASSERT(data.type_ == MATCHY_DATA_TYPE_BOOLEAN, "Should be boolean type");
        ASSERT(data.value.boolean == true, "is_vpn should be true");
        
        // Test false value
        const char *path_false[] = {"is_proxy", NULL};
        status = matchy_aget_value(&entry, &data, path_false);
        
        ASSERT(status == MATCHY_SUCCESS, "Should get is_proxy");
        ASSERT(data.type_ == MATCHY_DATA_TYPE_BOOLEAN, "Should be boolean type");
        ASSERT(data.value.boolean == false, "is_proxy should be false");
        
        printf("  is_vpn: %s, is_proxy: %s\n", 
               data.value.boolean ? "true" : "false",
               data.value.boolean ? "true" : "false");
    }
    
    matchy_free_result(&result);
    END_TEST();
}

void test_result_to_json(matchy_t *db) {
    TEST("matchy_result_to_json");
    
    matchy_result_t result = matchy_query(db, "8.8.8.8");
    ASSERT(result.found, "Query should find 8.8.8.8");
    
    if (result.found) {
        char *json = matchy_result_to_json(&result);
        ASSERT(json != NULL, "Should return JSON string");
        
        if (json) {
            ASSERT(strlen(json) > 0, "JSON should not be empty");
            ASSERT(strstr(json, "country") != NULL, "JSON should contain 'country'");
            ASSERT(strstr(json, "iso_code") != NULL, "JSON should contain 'iso_code'");
            ASSERT(strstr(json, "US") != NULL, "JSON should contain 'US'");
            
            printf("  JSON length: %zu\n", strlen(json));
            printf("  JSON preview: %.100s%s\n", json, strlen(json) > 100 ? "..." : "");
            
            matchy_free_string(json);
        }
    }
    
    matchy_free_result(&result);
    END_TEST();
}

void test_result_to_json_not_found(matchy_t *db) {
    TEST("matchy_result_to_json with not found result");
    
    matchy_result_t result = matchy_query(db, "11.11.11.11");
    ASSERT(!result.found, "Query should not find 11.11.11.11");
    
    char *json = matchy_result_to_json(&result);
    ASSERT(json == NULL, "Should return NULL for not found result");
    
    matchy_free_result(&result);
    END_TEST();
}

void test_get_entry_data_list(matchy_t *db) {
    TEST("matchy_get_entry_data_list");
    
    matchy_result_t result = matchy_query(db, "1.1.1.1");
    if (result.found) {
        matchy_entry_s entry;
        matchy_result_get_entry(&result, &entry);
        
        matchy_entry_data_list_t *list = NULL;
        int status = matchy_get_entry_data_list(&entry, &list);
        
        ASSERT(status == MATCHY_SUCCESS, "Should successfully get entry data list");
        ASSERT(list != NULL, "List should not be NULL");
        
        if (list) {
            // Count nodes
            int count = 0;
            matchy_entry_data_list_t *current = list;
            while (current != NULL) {
                count++;
                
                // Print info about each node
                if (count == 1) {
                    printf("  List nodes:\n");
                }
                printf("    Node %d: type=%u, has_data=%d\n", 
                       count, current->entry_data.type_, current->entry_data.has_data);
                
                current = current->next;
            }
            
            ASSERT(count > 0, "Should have at least one node");
            printf("  Total nodes: %d\n", count);
            
            matchy_free_entry_data_list(list);
        }
    }
    
    matchy_free_result(&result);
    END_TEST();
}

void test_get_entry_data_list_complex(matchy_t *db) {
    TEST("matchy_get_entry_data_list - complex nested structure");
    
    matchy_result_t result = matchy_query(db, "8.8.8.8");
    if (result.found) {
        matchy_entry_s entry;
        matchy_result_get_entry(&result, &entry);
        
        matchy_entry_data_list_t *list = NULL;
        int status = matchy_get_entry_data_list(&entry, &list);
        
        ASSERT(status == MATCHY_SUCCESS, "Should successfully get entry data list");
        ASSERT(list != NULL, "List should not be NULL");
        
        if (list) {
            int count = 0;
            int string_count = 0;
            int double_count = 0;
            int map_count = 0;
            
            matchy_entry_data_list_t *current = list;
            while (current != NULL) {
                count++;
                
                switch (current->entry_data.type_) {
                    case MATCHY_DATA_TYPE_UTF8_STRING:
                        string_count++;
                        break;
                    case MATCHY_DATA_TYPE_DOUBLE:
                        double_count++;
                        break;
                    case MATCHY_DATA_TYPE_MAP:
                        map_count++;
                        break;
                }
                
                current = current->next;
            }
            
            printf("  Total nodes: %d\n", count);
            printf("  String nodes: %d\n", string_count);
            printf("  Double nodes: %d\n", double_count);
            printf("  Map nodes: %d\n", map_count);
            
            ASSERT(count > 5, "Complex structure should have multiple nodes");
            ASSERT(string_count > 0, "Should have string values");
            ASSERT(map_count > 0, "Should have map structures");
            
            matchy_free_entry_data_list(list);
        }
    }
    
    matchy_free_result(&result);
    END_TEST();
}

void test_numeric_types(matchy_t *db) {
    TEST("matchy_aget_value - various numeric types");
    
    matchy_result_t result = matchy_query(db, "192.168.1.1");
    if (result.found) {
        matchy_entry_s entry;
        matchy_result_get_entry(&result, &entry);
        
        // Test float
        matchy_entry_data_t data;
        const char *path_float[] = {"float_val", NULL};
        int status = matchy_aget_value(&entry, &data, path_float);
        
        if (status == MATCHY_SUCCESS) {
            ASSERT(data.type_ == MATCHY_DATA_TYPE_FLOAT || data.type_ == MATCHY_DATA_TYPE_DOUBLE, 
                   "Should be float or double type");
            printf("  float_val retrieved successfully\n");
        }
        
        // Test double
        const char *path_double[] = {"double_val", NULL};
        status = matchy_aget_value(&entry, &data, path_double);
        
        if (status == MATCHY_SUCCESS) {
            ASSERT(data.type_ == MATCHY_DATA_TYPE_DOUBLE, "Should be double type");
            printf("  double_val: %.15f\n", data.value.double_value);
        }
    }
    
    matchy_free_result(&result);
    END_TEST();
}

void test_null_parameters(matchy_t *db) {
    TEST("NULL parameter handling");
    
    matchy_result_t result = matchy_query(db, "8.8.8.8");
    if (result.found) {
        matchy_entry_s entry;
        matchy_result_get_entry(&result, &entry);
        
        // Test NULL entry_data
        const char *path[] = {"country", "iso_code", NULL};
        int status = matchy_aget_value(&entry, NULL, path);
        ASSERT(status == MATCHY_ERROR_INVALID_PARAM, 
               "Should return error for NULL entry_data");
        
        // Test NULL path
        matchy_entry_data_t data;
        status = matchy_aget_value(&entry, &data, NULL);
        ASSERT(status == MATCHY_ERROR_INVALID_PARAM, 
               "Should return error for NULL path");
    }
    
    // Test NULL result
    int status = matchy_result_get_entry(NULL, NULL);
    ASSERT(status == MATCHY_ERROR_INVALID_PARAM, 
           "Should return error for NULL result");
    
    matchy_free_result(&result);
    END_TEST();
}

int main() {
    printf("========================================\n");
    printf("Matchy C API Extensions Test Suite\n");
    printf("========================================\n\n");
    
    // Create test database
    printf("Creating test database...\n");
    if (create_test_database() != 0) {
        fprintf(stderr, "Failed to create test database\n");
        return 1;
    }
    printf("✓ Test database created\n");
    
    // Open database
    matchy_t *db = matchy_open(TEST_DB_PATH);
    if (db == NULL) {
        fprintf(stderr, "Failed to open test database\n");
        return 1;
    }
    printf("✓ Database opened\n");
    
    // Run tests
    test_result_get_entry(db);
    test_result_get_entry_not_found(db);
    test_aget_value_nested_string(db);
    test_aget_value_double(db);
    test_aget_value_uint32(db);
    test_aget_value_invalid_path(db);
    test_aget_value_boolean(db);
    test_result_to_json(db);
    test_result_to_json_not_found(db);
    test_get_entry_data_list(db);
    test_get_entry_data_list_complex(db);
    test_numeric_types(db);
    test_null_parameters(db);
    
    // Cleanup
    matchy_close(db);
    
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
