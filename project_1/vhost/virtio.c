/* virtio.c: STUDENT IMPLEMENTATION FILE for Project 1 (Part III).
 *
 * In Part II you invented a device protocol (MMIO registers). Here you implement
 * the one the whole world actually uses: a virtio split virtqueue, driven by a
 * REAL QEMU virtual machine, whose stock virtio_console driver talks to your
 * code with no guest-side changes at all.
 *
 * The provided backend (backend.c) speaks the vhost-user protocol to QEMU, maps
 * the guest's memory, sets up the rings, and calls you every time the guest
 * kicks the queue. Everything below the seam is yours: TWO functions.
 *
 * WHAT IS PROVIDED: virtq.h (the ring structures, the memory map, the log sink),
 * backend.c (all vhost-user plumbing), run-qemu.sh (boots the VM).
 *
 * ============================================================================
 * TASK (a): virtq_gpa_to_hva(), the hypervisor's address translation.
 * ============================================================================
 * You wrote this once already: vmm_gpa_to_host() in Part I. This is the same
 * contract against a real hypervisor's memory map, except now there can be
 * SEVERAL regions with GAPS between them (see `struct virtq_mem` in virtq.h).
 *
 * Return a host pointer for [gpa, gpa+len), or NULL unless the range lies
 * ENTIRELY inside ONE region. The guest picks these numbers, so reject:
 *   - a range that runs off the end of its region (no straddling two regions),
 *   - an address in a gap between regions, or outside all of them,
 *   - a gpa + len that overflows.
 * Get this wrong and the guest can make your hypervisor read (or crash on)
 * memory that is not its own.
 *
 * ============================================================================
 * TASK (b): vlog_virtq_handle(), the virtqueue.
 * ============================================================================
 * For every chain the guest has made available:
 *
 *   1. Read the head index from the AVAIL ring:
 *          head = vq->avail->ring[vq->last_avail % vq->num]
 *      (First read vq->avail->idx to see how many are ready, and virtq_rmb()
 *      before you trust the ring contents.)
 *   2. Walk the DESCRIPTOR CHAIN from `head`. For each descriptor:
 *        - VRING_DESC_F_WRITE set  -> it is space for the DEVICE to write into.
 *          This queue is guest->host, so it carries no data: skip it.
 *        - VRING_DESC_F_INDIRECT set -> it is not data either! `d->addr` points
 *          at a TABLE of further descriptors in guest memory (`d->len` bytes of
 *          them, so d->len / sizeof(struct vring_desc) entries), which form
 *          their own chain starting at index 0. Translate the table and walk it.
 *          (Indirect tables do not nest.)
 *        - otherwise it is data: translate d->addr with
 *              virtq_gpa_to_hva(mem, d->addr, d->len)
 *          (CHECK FOR NULL) and append its bytes to the record.
 *        - follow d->next while VRING_DESC_F_NEXT is set.
 *      Concatenate the chain's bytes into one record, capped at VIRTQ_MAX_RECORD
 *      (never overflow your buffer).
 *   3. Emit it:  vlog_sink_emit(sink, bytes, len);
 *   4. COMPLETE the chain on the USED ring:
 *          vq->used->ring[vq->used->idx % vq->num] = { .id = head, .len = 0 };
 *          virtq_wmb();
 *          vq->used->idx++;
 *      (This is the virtio equivalent of the Part II STATUS/SEQ readback: it is
 *      how the driver learns its buffer is free again. Get it wrong and the
 *      guest hangs after a few writes.)
 *   5. Advance vq->last_avail and count the chain.
 *
 * Return the number of chains you completed; the backend raises the guest's
 * interrupt when that is > 0.
 *
 * SAFETY: the rings live in memory the GUEST owns and can change at any time. A
 * descriptor index, a chain, or a length can be nonsense. Bounds-check every
 * index against the table size, check every translation, and never loop forever
 * on a cyclic chain. A hypervisor must not be crashable by its guest.
 *
 * See SPEC.md Part III. Develop against `cd tests && ./run_virtq_tests.sh`, then
 * watch it drive a real VM with `cd vhost && ./run-qemu.sh`.
 */
#include "virtq.h"

#include <string.h>

/* ---- (a) guest-physical -> host-virtual -------------------------------- */

void *virtq_gpa_to_hva(const struct virtq_mem *mem, uint64_t gpa, uint64_t len)
{
    (void)mem; (void)gpa; (void)len;

    /* TODO(student): find the region that fully contains [gpa, gpa+len) and
     * return the host pointer for it; otherwise return NULL. See the notes
     * above, and remember what vmm_gpa_to_host() had to guard against. */
    if (len == 0) {
        return NULL;
    }
    for (int i = 0; i < mem->nregions; i++) {
        if (gpa >= mem->regions[i].gpa) {
            // check for int overflow and within bounds (inclusive)
            if (((UINT64_MAX - gpa) > len) && ((gpa + len) <= (mem->regions[i].gpa + mem->regions[i].size))) {
                return mem->regions[i].hva + (gpa - mem->regions[i].gpa);
            }
        }
    }

    return NULL;
}

/* ---- (b) the virtqueue ------------------------------------------------- */

int vlog_virtq_handle(struct virtq *vq, const struct virtq_mem *mem,
                      struct vlog_sink *sink)
{
    (void)vq; (void)mem; (void)sink;

    /* TODO(student): process every available chain (see the recipe above) and
     * return how many you completed. */

    __virtio16 idx = vq->avail->idx;
    virtq_rmb();
    uint32_t count = 0;
    
    while (vq->last_avail < idx) {
        uint32_t hop_count = 0;
        char rec[VIRTQ_MAX_RECORD]; 
        __virtio16 rec_idx = 0;

        __virtio16 head = vq->avail->ring[vq->last_avail % vq->num]; // looping through the chain
        __virtio16 temp = head;
        // loop through descriptor table 
        while (temp < vq->num && hop_count < vq->num) {
            uint32_t indirect_hops = 0;
            struct vring_desc d = vq->desc[temp];

            // skip writable descriptors
            if ((d.flags & VRING_DESC_F_WRITE) == 0) {
                // indirect descriptor table
                if (d.flags & VRING_DESC_F_INDIRECT) {
                    struct vring_desc *indirect_table = virtq_gpa_to_hva(mem, d.addr, d.len);
                    
                    if (indirect_table) {
                        __virtio16 indirect_head = 0;

                        uint16_t num_entries = d.len / sizeof(struct vring_desc);
                        while (indirect_head <  num_entries && indirect_hops < num_entries) {
                            struct vring_desc indirect_d = indirect_table[indirect_head];

                            if ((indirect_d.flags & VRING_DESC_F_WRITE) == 0) {
                                void *hva_addr = virtq_gpa_to_hva(mem, indirect_d.addr, indirect_d.len);

                                if (hva_addr && (rec_idx + indirect_d.len <= VIRTQ_MAX_RECORD)) {
                                    memcpy(rec + rec_idx, hva_addr, indirect_d.len); 
                                    rec_idx += indirect_d.len;
                                }
                            }

                            if (indirect_d.flags & VRING_DESC_F_NEXT) {
                                indirect_head = indirect_d.next;
                            } else {
                                break;
                            }
                            indirect_hops++;
                        }
                    }

                } else {
                    // data: append bytes
                    void *hva_addr = virtq_gpa_to_hva(mem, d.addr, d.len);

                    if (hva_addr && (rec_idx + d.len <= VIRTQ_MAX_RECORD)) {
                        memcpy(rec + rec_idx, hva_addr, d.len); 
                        rec_idx += d.len;
                    }
                }
            }

            if (d.flags & VRING_DESC_F_NEXT) {
                temp = d.next;
            } else {
                break;
            }
            hop_count++;
        }

        vlog_sink_emit(sink, rec, rec_idx);

        vq->used->ring[vq->used->idx % vq->num].id = head;
        vq->used->ring[vq->used->idx % vq->num].len = 0;
        virtq_wmb();
        vq->used->idx++;

        vq->last_avail++;
        count++;
    }


    return count;
}

