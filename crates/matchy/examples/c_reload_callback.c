/*
 * Matchy C API - Auto-Reload with Callback Example
 *
 * This example demonstrates:
 * - Opening a database with auto-reload enabled
 * - Setting up a callback to be notified of reload events
 * - Modifying the database file to trigger a reload
 * - Receiving reload success/failure notifications
 *
 * Build:
 *   gcc -o c_reload_callback examples/c_reload_callback.c \
 *       -I./include -L./target/release -lmatchy -lpthread -ldl -lm
 *
 * Run:
 *   LD_LIBRARY_PATH=./target/release ./c_reload_callback
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "matchy/matchy.h"

/* Track reload events */
typedef struct {
    int reload_count;
    int success_count;
    int failure_count;
} reload_stats_t;

/* Reload callback - called when database reloads */
void on_reload(const matchy_reload_event_t *event, void *user_data) {
    reload_stats_t *stats = (reload_stats_t *)user_data;
    
    stats->reload_count++;
    
    if (event->success) {
        stats->success_count++;
        printf("✅ Database reloaded successfully!\n");
        printf("   Path: %s\n", event->path);
        printf("   Generation: %lu\n", event->generation);
    } else {
        stats->failure_count++;
        printf("❌ Database reload failed!\n");
        printf("   Path: %s\n", event->path);
        printf("   Error: %s\n", event->error);
    }
    printf("\n");
}

int main(void) {
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("   MATCHY C API - AUTO-RELOAD WITH CALLBACK DEMO\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
    
    /* Create test database */
    const char *db_path = "/tmp/test_reload.mxy";
    printf("Creating test database: %s\n", db_path);
    
    matchy_builder_t *builder = matchy_builder_new();
    if (builder == NULL) {
        fprintf(stderr, "Failed to create builder\n");
        return 1;
    }
    
    /* Add test data */
    matchy_builder_add(builder, "192.168.1.1", "{\"version\": 1}");
    matchy_builder_add(builder, "example.com", "{\"type\": \"domain\"}");
    
    /* Build and save */
    uint8_t *buffer = NULL;
    size_t size = 0;
    if (matchy_builder_build(builder, &buffer, &size) != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to build database\n");
        matchy_builder_free(builder);
        return 1;
    }
    matchy_builder_free(builder);
    
    /* Write to file */
    FILE *f = fopen(db_path, "wb");
    if (f == NULL) {
        fprintf(stderr, "Failed to open file for writing\n");
        free(buffer);
        return 1;
    }
    fwrite(buffer, 1, size, f);
    fclose(f);
    free(buffer);
    
    printf("Database created successfully\n\n");
    
    /* Initialize reload stats */
    reload_stats_t stats = {0, 0, 0};
    
    /* Open database with auto-reload and callback */
    printf("Opening database with auto-reload and callback...\n");
    matchy_open_options_t opts;
    matchy_init_open_options(&opts);
    opts.auto_reload = true;                    /* Enable auto-reload */
    opts.reload_callback = on_reload;           /* Set callback function */
    opts.reload_callback_user_data = &stats;    /* Pass our stats struct */
    
    matchy_t *db = matchy_open_with_options(db_path, &opts);
    if (db == NULL) {
        fprintf(stderr, "Failed to open database\n");
        unlink(db_path);
        return 1;
    }
    
    printf("Database opened with auto-reload enabled\n\n");
    
    /* Test initial lookup */
    printf("Testing initial lookup:\n");
    matchy_result_t result;
    matchy_lookup(db, "192.168.1.1", &result);
    printf("  192.168.1.1: %s\n", result.found ? "Found" : "Not found");
    matchy_lookup(db, "example.com", &result);
    printf("  example.com: %s\n\n", result.found ? "Found" : "Not found");
    
    /* Modify database to trigger reload */
    printf("Modifying database file to trigger reload...\n");
    sleep(1);  /* Wait a bit to ensure file watcher is active */
    
    builder = matchy_builder_new();
    matchy_builder_add(builder, "10.0.0.1", "{\"version\": 2}");
    matchy_builder_add(builder, "new-domain.com", "{\"type\": \"new\"}");
    matchy_builder_build(builder, &buffer, &size);
    matchy_builder_free(builder);
    
    f = fopen(db_path, "wb");
    fwrite(buffer, 1, size, f);
    fclose(f);
    free(buffer);
    
    /* Wait for reload (file watcher has 200ms debounce + reload time) */
    printf("Waiting for reload to complete...\n\n");
    sleep(1);
    
    /* Test lookup after reload */
    printf("Testing lookup after reload:\n");
    matchy_lookup(db, "10.0.0.1", &result);
    printf("  10.0.0.1 (new): %s\n", result.found ? "Found" : "Not found");
    matchy_lookup(db, "new-domain.com", &result);
    printf("  new-domain.com (new): %s\n", result.found ? "Found" : "Not found");
    matchy_lookup(db, "192.168.1.1", &result);
    printf("  192.168.1.1 (old): %s\n\n", result.found ? "Found" : "Not found");
    
    /* Print reload statistics */
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("   RELOAD STATISTICS\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Total reloads:       %d\n", stats.reload_count);
    printf("Successful reloads:  %d\n", stats.success_count);
    printf("Failed reloads:      %d\n", stats.failure_count);
    printf("\n");
    
    if (stats.reload_count > 0) {
        printf("✅ Callback mechanism is working!\n");
    } else {
        printf("⚠️  No reloads detected (may need more time)\n");
    }
    
    /* Cleanup */
    matchy_close(db);
    unlink(db_path);
    
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("   DEMO COMPLETE\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    
    return 0;
}
