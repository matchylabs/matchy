/**
 * Example: Auto-reload database on file changes
 *
 * Demonstrates how to enable automatic reloading when the database
 * file is updated. Useful for long-running services that need to
 * pick up threat intelligence updates without restarting.
 *
 * Compile:
 *   gcc -o auto_reload c_auto_reload_example.c \
 *       -I../include/matchy \
 *       -L../target/release \
 *       -lmatchy \
 *       -lpthread -ldl -lm
 *
 * Run:
 *   ./auto_reload threats.mxy
 *
 * In another terminal, update the database:
 *   cp new_threats.mxy threats.mxy
 *
 * The program will automatically use the new database!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "matchy.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <database.mxy>\n", argv[0]);
        return 1;
    }

    const char *db_path = argv[1];

    // Configure database with auto-reload enabled
    matchy_open_options_t opts;
    matchy_init_open_options(&opts);
    opts.cache_capacity = 10000;
    opts.auto_reload = true;  // Enable automatic reload on file changes

    printf("Opening database with auto-reload: %s\n", db_path);
    matchy_t *db = matchy_open_with_options(db_path, &opts);
    if (db == NULL) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }

    printf("Database opened successfully!\n");
    printf("Queries will automatically use the latest version when file changes.\n");
    printf("\n");
    printf("Try updating the database file (cp new_db.mxy %s) while this runs.\n", db_path);
    printf("\n");

    // Query loop - demonstrates transparent reload
    const char *test_queries[] = {
        "1.2.3.4",
        "192.168.1.1",
        "evil.com",
        "test.example.com",
        NULL
    };

    int iteration = 0;
    while (1) {
        iteration++;
        printf("\n[Iteration %d]\n", iteration);

        for (int i = 0; test_queries[i] != NULL; i++) {
            matchy_result_t result;
            const char *query = test_queries[i];

            if (matchy_lookup(db, query, &result) == MATCHY_SUCCESS) {
                if (result.found) {
                    printf("  ✓ %s: MATCH (prefix_len=%u)\n", 
                           query, result.prefix_len);
                } else {
                    printf("  ✗ %s: not found\n", query);
                }
            } else {
                printf("  ! %s: lookup error\n", query);
            }
        }

        // Get statistics
        matchy_stats_t stats;
        matchy_get_stats(db, &stats);
        
        double cache_hit_rate = 0.0;
        uint64_t total_cache_ops = stats.cache_hits + stats.cache_misses;
        if (total_cache_ops > 0) {
            cache_hit_rate = (double)stats.cache_hits / total_cache_ops * 100.0;
        }

        printf("\nStatistics:\n");
        printf("  Total queries: %llu\n", stats.total_queries);
        printf("  Cache hit rate: %.1f%%\n", cache_hit_rate);
        printf("  IP queries: %llu, String queries: %llu\n", 
               stats.ip_queries, stats.string_queries);

        printf("\nWaiting 5 seconds... (update database file now if you want)\n");
        sleep(5);
    }

    // Cleanup (never reached in this example, but good practice)
    matchy_free(db);
    return 0;
}
