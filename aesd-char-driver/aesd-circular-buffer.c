/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#endif

#include "aesd-circular-buffer.h"

#define D_DEBUG 0
/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /**
    * TODO: implement per description
    */
    uint8_t count = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - (buffer->in_offs - buffer->out_offs);
    uint8_t index = buffer->out_offs;
    struct aesd_buffer_entry *entry;
  
#if D_DEBUG
    printf("Find from %d\n", count);
#endif
    while (count--) {
       entry = &buffer->entry[index];
       if (entry->size <= char_offset)
           char_offset -= entry->size;
       else {
           if (entry_offset_byte_rtn)
               *entry_offset_byte_rtn = char_offset;
#if D_DEBUG
           printf("Find %s\n", entry->buffptr);
#endif
           return entry;
       }
       if (++index >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
           index = 0;
#if D_DEBUG
       printf("Find from left %d\n", count);
#endif
    }
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */
    char *ptr;
    assert(add_entry!=NULL);
    if (buffer->full == 0) {
#if D_DEBUG
        printf("Enter element\n");
#endif
        memcpy(&(buffer->entry[buffer->in_offs]), add_entry, sizeof(struct aesd_buffer_entry));
        ptr = strdup(add_entry->buffptr);
        assert(ptr != NULL);
#if D_DEBUG
        printf("Enter element %s\n", ptr);
#endif
        buffer->entry[buffer->in_offs].buffptr = ptr;
#if D_DEBUG
        printf("Struct buffer out:%d in:%d ", buffer->out_offs, buffer->in_offs);
#endif
        buffer->in_offs = buffer->in_offs + 1;
        if (buffer->in_offs >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) 
            buffer->in_offs = 0;
        if (buffer->in_offs == buffer->out_offs)
            buffer->full = 1;
#if D_DEBUG
        printf("After out:%d in:%d\n", buffer->out_offs, buffer->in_offs);
#endif
    }
    else {
#if !defined( __KERNEL__ )
        free((void*)(buffer->entry[buffer->out_offs].buffptr));
#else
        kfree((void*)(buffer->entry[buffer->out_offs].buffptr));
#endif
#if D_DEBUG
        printf("Enter element full\n");
#endif
        memcpy(&(buffer->entry[buffer->in_offs]), add_entry, sizeof(struct aesd_buffer_entry));
        ptr = strdup(add_entry->buffptr);
        assert(ptr != NULL);
#if D_DEBUG
        printf("Enter element full %s\n", ptr);
#endif
        buffer->entry[buffer->in_offs].buffptr = ptr;
#if D_DEBUG
        printf("Struct buffer full out:%d in:%d ", buffer->out_offs, buffer->in_offs);
#endif
        buffer->in_offs = buffer->in_offs + 1;
        if (buffer->in_offs >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) 
            buffer->in_offs = 0;
        buffer->out_offs = buffer->in_offs;
#if D_DEBUG
        printf("After out:%d in:%d\n", buffer->out_offs, buffer->in_offs);
#endif
    }
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
