#include "common.h"
#include "ndpi_api.h"
#include "ndpi_typedefs.h"
#include <sys/param.h>
#include <uthash.h>

flow_table_t *find_flow(flow_t key);
flow_table_t *add_flow(flow_t key, struct ndpi_flow_struct *ndpi_flow);
void remove_flow(flow_t key);

// Return the head of the identified flow table for iteration 
flow_table_t *get_flow_table_head(void);

// Unknown flow table operations
ukw_flow_table_t *find_ukw_flow(flow_t key);
ukw_flow_table_t *add_ukw_flow(flow_t key);
void remove_ukw_flow(flow_t key);

/* Promote an unknown flow entry to the identified flow table
 * Seeds the global Markov model from the buffer before promoting.
 * Returns pointer to the newly promoted flow_table_t, or NULL on failure
 */
flow_table_t *promote_ukw_to_identified(flow_t key, ukw_flow_table_t *ukw_entry, CaptureContext *ctx);

// Compute the Markov state from packet direction and caplen
uint8_t compute_markov_state(int direction, uint16_t caplen);

// Normalize the Markov transition count matrix into a probability matrix
void normalize_markov_matrix(const uint32_t count_matrix[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE],
                             double prob_matrix[MARKOV_STATE_SPACE][MARKOV_STATE_SPACE]);
