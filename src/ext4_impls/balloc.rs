use crate::ext4_defs::*;
use crate::prelude::*;
use crate::return_errno_with_message;
use crate::utils::bitmap::*;
use core::array;

// Cache for block group information
#[derive(Clone, Copy)]
struct BlockGroupCache {
    bitmap: [u8; BLOCK_SIZE],
    free_blocks: u64,
    last_used_idx: u32,
}

impl BlockGroupCache {
    fn new(bitmap: &[u8], free_blocks: u64) -> Self {
        let mut new_bitmap = [0u8; BLOCK_SIZE];
        new_bitmap.copy_from_slice(bitmap);
        Self {
            bitmap: new_bitmap,
            free_blocks,
            last_used_idx: 0,
        }
    }
}

// Simple fixed-size cache for block groups
struct BlockGroupCacheManager {
    caches: [(u32, BlockGroupCache); 8], // Cache for up to 8 block groups
    len: usize,
}

impl BlockGroupCacheManager {
    fn new() -> Self {
        let empty_cache = BlockGroupCache {
            bitmap: [0; BLOCK_SIZE],
            free_blocks: 0,
            last_used_idx: 0,
        };
        Self {
            caches: array::from_fn(|_| (0, empty_cache)),
            len: 0,
        }
    }

    fn get(&mut self, bgid: u32) -> Option<&mut BlockGroupCache> {
        for i in 0..self.len {
            if self.caches[i].0 == bgid {
                return Some(&mut self.caches[i].1);
            }
        }
        None
    }

    fn insert(&mut self, bgid: u32, cache: BlockGroupCache) {
        if self.len < 8 {
            self.caches[self.len] = (bgid, cache);
            self.len += 1;
        } else {
            // Simple LRU: remove the first entry and shift others
            for i in 0..self.len-1 {
                self.caches[i] = self.caches[i+1];
            }
            self.caches[self.len-1] = (bgid, cache);
        }
    }

    fn iter_caches(&self) -> impl Iterator<Item = &(u32, BlockGroupCache)> {
        self.caches[..self.len].iter()
    }
}

impl Ext4 {
    /// Compute number of block group from block address.
    ///
    /// Params:
    ///
    /// `baddr` - Absolute address of block.
    ///
    /// # Returns
    /// `u32` - Block group index
    pub fn get_bgid_of_block(&self, baddr: u64) -> u32 {
        let mut baddr = baddr;
        if self.super_block.first_data_block() != 0 && baddr != 0 {
            baddr -= 1;
        }
        (baddr / self.super_block.blocks_per_group() as u64) as u32
    }

    /// Compute the starting block address of a block group.
    ///
    /// Params:
    /// `bgid` - Block group index
    ///
    /// Returns:
    /// `u64` - Block address
    pub fn get_block_of_bgid(&self, bgid: u32) -> u64 {
        let mut baddr = 0;
        if self.super_block.first_data_block() != 0 {
            baddr += 1;
        }
        baddr + bgid as u64 * self.super_block.blocks_per_group() as u64
    }

    /// Convert block address to relative index in block group.
    ///
    /// Params:
    /// `baddr` - Block number to convert.
    ///
    /// Returns:
    /// `u32` - Relative number of block.
    pub fn addr_to_idx_bg(&self, baddr: u64) -> u32 {
        let mut baddr = baddr;
        if self.super_block.first_data_block() != 0 && baddr != 0 {
            baddr -= 1;
        }
        (baddr % self.super_block.blocks_per_group() as u64) as u32
    }

    /// Convert relative block address in group to absolute address.
    ///
    /// # Arguments
    ///
    /// * `index` - Relative block address.
    /// * `bgid` - Block group.
    ///
    /// # Returns
    ///
    /// * `Ext4Fsblk` - Absolute block address.
    pub fn bg_idx_to_addr(&self, index: u32, bgid: u32) -> Ext4Fsblk {
        let mut index = index;
        if self.super_block.first_data_block() != 0 {
            index += 1;
        }
        (self.super_block.blocks_per_group() as u64 * bgid as u64) + index as u64
    }


    /// Allocate a new block.
    ///
    /// Params:
    /// `inode_ref` - Reference to the inode.
    /// `goal` - Absolute address of the block.
    ///
    /// Returns:
    /// `Result<Ext4Fsblk>` - The physical block number allocated.
    pub fn balloc_alloc_block(
        &self,
        inode_ref: &mut Ext4InodeRef,
        goal: Option<Ext4Fsblk>,
    ) -> Result<Ext4Fsblk> {
        let mut alloc: Ext4Fsblk = 0;
        let super_block = &self.super_block;
        let blocks_per_group = super_block.blocks_per_group();
        let mut bgid;
        let mut idx_in_bg;

        if let Some(goal) = goal {
            bgid = self.get_bgid_of_block(goal);
            idx_in_bg = self.addr_to_idx_bg(goal);
        } else {
            bgid = 1;
            idx_in_bg = 0;
        }

        let block_group_count = super_block.block_group_count();
        let mut count = block_group_count;

        while count > 0 {
            // Load block group reference
            let mut block_group =
                Ext4BlockGroup::load_new(self.block_device.clone(), super_block, bgid as usize);

            let free_blocks = block_group.get_free_blocks_count();
            if free_blocks == 0 {
                // Try next block group
                bgid = (bgid + 1) % block_group_count;
                count -= 1;

                if count == 0 {
                    log::trace!("No free blocks available in all block groups");
                    return_errno_with_message!(Errno::ENOSPC, "No free blocks available in all block groups");
                }
                continue;
            }

            // Compute indexes
            let first_in_bg = self.get_block_of_bgid(bgid);
            let first_in_bg_index = self.addr_to_idx_bg(first_in_bg);

            if idx_in_bg < first_in_bg_index {
                idx_in_bg = first_in_bg_index;
            }

            // Load block with bitmap
            let bmp_blk_adr = block_group.get_block_bitmap_block(super_block);
            let mut bitmap_block =
                Block::load(self.block_device.clone(), bmp_blk_adr as usize * BLOCK_SIZE);

            // Check if goal is free
            if ext4_bmap_is_bit_clr(&bitmap_block.data, idx_in_bg) {
                ext4_bmap_bit_set(&mut bitmap_block.data, idx_in_bg);
                block_group.set_block_group_balloc_bitmap_csum(super_block, &bitmap_block.data);
                self.block_device
                    .write_offset(bmp_blk_adr as usize * BLOCK_SIZE, &bitmap_block.data);
                alloc = self.bg_idx_to_addr(idx_in_bg, bgid);

                /* Update free block counts */
                self.update_free_block_counts(inode_ref, &mut block_group, bgid as usize)?;
                return Ok(alloc);
            }

            // Try to find free block near to goal
            let blk_in_bg = blocks_per_group;
            let end_idx = min((idx_in_bg + 63) & !63, blk_in_bg);

            for tmp_idx in (idx_in_bg + 1)..end_idx {
                if ext4_bmap_is_bit_clr(&bitmap_block.data, tmp_idx) {
                    ext4_bmap_bit_set(&mut bitmap_block.data, tmp_idx);
                    block_group.set_block_group_balloc_bitmap_csum(super_block, &bitmap_block.data);
                    self.block_device
                        .write_offset(bmp_blk_adr as usize * BLOCK_SIZE, &bitmap_block.data);
                    alloc = self.bg_idx_to_addr(tmp_idx, bgid);
                    self.update_free_block_counts(inode_ref, &mut block_group, bgid as usize)?;
                    return Ok(alloc);
                }
            }

            // Find free bit in bitmap
            let mut rel_blk_idx = 0;
            if ext4_bmap_bit_find_clr(&bitmap_block.data, idx_in_bg, blk_in_bg, &mut rel_blk_idx) {
                ext4_bmap_bit_set(&mut bitmap_block.data, rel_blk_idx);
                block_group.set_block_group_balloc_bitmap_csum(super_block, &bitmap_block.data);
                self.block_device
                    .write_offset(bmp_blk_adr as usize * BLOCK_SIZE, &bitmap_block.data);
                alloc = self.bg_idx_to_addr(rel_blk_idx, bgid);
                self.update_free_block_counts(inode_ref, &mut block_group, bgid as usize)?;
                return Ok(alloc);
            }

            // No free block found in this group, try other block groups
            bgid = (bgid + 1) % block_group_count;
            count -= 1;
        }

        return_errno_with_message!(Errno::ENOSPC, "No free blocks available in all block groups");
    }

    /// Allocate a new block start from a specific bgid
    ///
    /// Params:
    /// `inode_ref` - Reference to the inode.
    /// `start_bgid` - Start bgid of free block search
    ///
    /// Returns:
    /// `Result<Ext4Fsblk>` - The physical block number allocated.
    pub fn balloc_alloc_block_from(
        &self,
        inode_ref: &mut Ext4InodeRef,
        start_bgid: &mut u32,
    ) -> Result<Ext4Fsblk> {
        let mut alloc: Ext4Fsblk = 0;
        let super_block = &self.super_block;
        let blocks_per_group = super_block.blocks_per_group();
        // Maximum number of blocks that can be represented by a bitmap block
        let max_blocks_in_bitmap = BLOCK_SIZE * 8;

        let mut bgid = *start_bgid;
        let mut idx_in_bg = 0;

        let block_group_count = super_block.block_group_count();
        let mut count = block_group_count;

        while count > 0 {
            // Load block group reference
            let mut block_group =
                Ext4BlockGroup::load_new(self.block_device.clone(), super_block, bgid as usize);

            let free_blocks = block_group.get_free_blocks_count();
            if free_blocks == 0 {
                // Try next block group
                bgid = (bgid + 1) % block_group_count;
                count -= 1;

                if count == 0 {
                    log::trace!("No free blocks available in all block groups");
                    return_errno_with_message!(Errno::ENOSPC, "No free blocks available in all block groups");
                }
                continue;
            }

            // Compute indexes
            let first_in_bg = self.get_block_of_bgid(bgid);
            let first_in_bg_index = self.addr_to_idx_bg(first_in_bg);

            if idx_in_bg < first_in_bg_index {
                idx_in_bg = first_in_bg_index;
            }

            // Ensure idx_in_bg doesn't exceed bitmap size
            if idx_in_bg >= max_blocks_in_bitmap as u32 {
                // Try next block group if we've reached the end of this bitmap
                bgid = (bgid + 1) % block_group_count;
                count -= 1;
                idx_in_bg = 0;
                continue;
            }

            // Load block with bitmap
            let bmp_blk_adr = block_group.get_block_bitmap_block(super_block);
            let mut bitmap_block =
                Block::load(self.block_device.clone(), bmp_blk_adr as usize * BLOCK_SIZE);

            // Check if goal is free
            if ext4_bmap_is_bit_clr(&bitmap_block.data, idx_in_bg) {
                ext4_bmap_bit_set(&mut bitmap_block.data, idx_in_bg);
                block_group.set_block_group_balloc_bitmap_csum(super_block, &bitmap_block.data);
                self.block_device
                    .write_offset(bmp_blk_adr as usize * BLOCK_SIZE, &bitmap_block.data);
                alloc = self.bg_idx_to_addr(idx_in_bg, bgid);

                /* Update free block counts */
                self.update_free_block_counts(inode_ref, &mut block_group, bgid as usize)?;

                *start_bgid = bgid;
                return Ok(alloc);
            }

            // Try to find free block near to goal
            let end_idx = min((idx_in_bg + 63) & !63, max_blocks_in_bitmap as u32);

            for tmp_idx in (idx_in_bg + 1)..end_idx {
                if ext4_bmap_is_bit_clr(&bitmap_block.data, tmp_idx) {
                    ext4_bmap_bit_set(&mut bitmap_block.data, tmp_idx);
                    block_group.set_block_group_balloc_bitmap_csum(super_block, &bitmap_block.data);
                    self.block_device
                        .write_offset(bmp_blk_adr as usize * BLOCK_SIZE, &bitmap_block.data);
                    alloc = self.bg_idx_to_addr(tmp_idx, bgid);
                    self.update_free_block_counts(inode_ref, &mut block_group, bgid as usize)?;

                    *start_bgid = bgid;
                    return Ok(alloc);
                }
            }

            // Find free bit in bitmap
            let mut rel_blk_idx = 0;
            if ext4_bmap_bit_find_clr(&bitmap_block.data, idx_in_bg, max_blocks_in_bitmap as u32, &mut rel_blk_idx) {
                ext4_bmap_bit_set(&mut bitmap_block.data, rel_blk_idx);
                block_group.set_block_group_balloc_bitmap_csum(super_block, &bitmap_block.data);
                self.block_device
                    .write_offset(bmp_blk_adr as usize * BLOCK_SIZE, &bitmap_block.data);
                alloc = self.bg_idx_to_addr(rel_blk_idx, bgid);
                self.update_free_block_counts(inode_ref, &mut block_group, bgid as usize)?;

                *start_bgid = bgid;
                return Ok(alloc);
            }

            // No free block found in this group, try other block groups
            bgid = (bgid + 1) % block_group_count;
            count -= 1;
            idx_in_bg = 0;
        }

        return_errno_with_message!(Errno::ENOSPC, "No free blocks available in all block groups");
    }

    fn update_free_block_counts(
        &self,
        inode_ref: &mut Ext4InodeRef,
        block_group: &mut Ext4BlockGroup,
        bgid: usize,
    ) -> Result<()> {
        let mut super_block = self.super_block;
        let block_size = BLOCK_SIZE as u64;

        // Update superblock free blocks count
        let mut super_blk_free_blocks = super_block.free_blocks_count();
        super_blk_free_blocks -= 1;
        super_block.set_free_blocks_count(super_blk_free_blocks);
        super_block.sync_to_disk_with_csum(self.block_device.clone());

        // Update inode blocks (different block size!) count
        let mut inode_blocks = inode_ref.inode.blocks_count();
        inode_blocks += block_size / EXT4_INODE_BLOCK_SIZE as u64;
        inode_ref.inode.set_blocks_count(inode_blocks);
        self.write_back_inode(inode_ref);

        // Update block group free blocks count
        let mut fb_cnt = block_group.get_free_blocks_count();
        fb_cnt -= 1;
        block_group.set_free_blocks_count(fb_cnt as u32);
        block_group.sync_to_disk_with_csum(self.block_device.clone(), bgid, &super_block);

        Ok(())
    }

    #[allow(unused)]
    pub fn balloc_free_blocks(&self, inode_ref: &mut Ext4InodeRef, start: Ext4Fsblk, count: u32) {
        // log::trace!("balloc_free_blocks start {:x?} count {:x?}", start, count);
        let mut count = count as usize;
        let mut start = start;

        let mut super_block = self.super_block;

        let blocks_per_group = super_block.blocks_per_group();

        let bgid = start / blocks_per_group as u64;

        let mut bg_first = start / blocks_per_group as u64;
        let mut bg_last = (start + count as u64 - 1) / blocks_per_group as u64;

        while bg_first <= bg_last {
            let idx_in_bg = start % blocks_per_group as u64;

            let mut bg =
                Ext4BlockGroup::load_new(self.block_device.clone(), &super_block, bgid as usize);

            let block_bitmap_block = bg.get_block_bitmap_block(&super_block);
            let mut raw_data = self
                .block_device
                .read_offset(block_bitmap_block as usize * BLOCK_SIZE);
            let mut data: &mut Vec<u8> = &mut raw_data;

            let mut free_cnt = BLOCK_SIZE * 8 - idx_in_bg as usize;

            if count > free_cnt {
            } else {
                free_cnt = count;
            }

            ext4_bmap_bits_free(data, idx_in_bg as u32, free_cnt as u32);

            count -= free_cnt;
            start += free_cnt as u64;

            bg.set_block_group_balloc_bitmap_csum(&super_block, data);
            self.block_device
                .write_offset(block_bitmap_block as usize * BLOCK_SIZE, data);

            /* Update superblock free blocks count */
            let mut super_blk_free_blocks = super_block.free_blocks_count();

            super_blk_free_blocks += free_cnt as u64;
            super_block.set_free_blocks_count(super_blk_free_blocks);
            super_block.sync_to_disk_with_csum(self.block_device.clone());

            /* Update inode blocks (different block size!) count */
            let mut inode_blocks = inode_ref.inode.blocks_count();

            inode_blocks -= (free_cnt  * (BLOCK_SIZE / EXT4_INODE_BLOCK_SIZE)) as u64;
            inode_ref.inode.set_blocks_count(inode_blocks);
            self.write_back_inode(inode_ref);

            /* Update block group free blocks count */
            let mut fb_cnt = bg.get_free_blocks_count();
            fb_cnt += free_cnt as u64;
            bg.set_free_blocks_count(fb_cnt as u32);
            bg.sync_to_disk_with_csum(self.block_device.clone(), bgid as usize, &super_block);

            bg_first += 1;
        }
    }

    /// Check if a block is a system reserved block
    pub fn is_system_reserved_block(&self, block_num: u64, bgid: u32) -> bool {
        // let super_block = &self.super_block;
        // let blocks_per_group = super_block.blocks_per_group() as u64;
        
        // // Skip superblock (block 0)
        // if block_num == 0 {
        //     return true;
        // }

        // // Skip block group descriptor blocks
        // let desc_blocks = (super_block.block_group_count() as u64 * size_of::<Ext4BlockGroup>() as u64 + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64;
        // if block_num < desc_blocks {
        //     return true;
        // }

        // // Get block group
        // let block_group = Ext4BlockGroup::load_new(self.block_device.clone(), super_block, bgid as usize);
        
        // // Skip block bitmap block
        // let bmp_blk = block_group.get_block_bitmap_block(super_block) as u64;
        // if block_num == bmp_blk {
        //     return true;
        // }

        // // Skip inode bitmap block
        // let inode_bmp_blk = block_group.get_inode_bitmap_block(super_block) as u64;
        // if block_num == inode_bmp_blk {
        //     return true;
        // }

        // // Skip inode table blocks
        // let inode_table_blk = block_group.get_inode_table_blk_num() as u64;
        // let inodes_per_group = super_block.inodes_per_group() as u64;
        // let inode_size = super_block.inode_size() as u64;
        // let inode_table_blocks = (inodes_per_group * inode_size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64;
        // if block_num >= inode_table_blk && block_num < inode_table_blk + inode_table_blocks {
        //     return true;
        // }

        false
    }


    /// Optimized block allocation inspired by lwext4
    /// 
    /// Params:
    /// `inode_ref` - Reference to the inode
    /// `start_bgid` - Starting block group ID, will be updated to the last used block group
    /// `count` - Number of blocks to allocate
    /// 
    /// Returns:
    /// `Result<Vec<Ext4Fsblk>>` - Vector of allocated physical block numbers
    pub fn balloc_alloc_block_batch(
        &self,
        inode_ref: &mut Ext4InodeRef,
        start_bgid: &mut u32,
        count: usize,
    ) -> Result<Vec<Ext4Fsblk>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        
        log::info!("[Block Alloc] Requesting {} blocks starting from bgid {}", count, *start_bgid);
        
        let super_block = &self.super_block;
        let block_group_count = super_block.block_group_count();
        
        // Validate inputs
        if block_group_count == 0 {
            log::error!("[Block Alloc] Invalid block group count: 0");
            return return_errno_with_message!(Errno::EINVAL, "Invalid block group count");
        }
        
        if *start_bgid >= block_group_count {
            log::warn!("[Block Alloc] Invalid start_bgid {}, resetting to 0", *start_bgid);
            *start_bgid = 0;
        }
        
        let mut bgid = *start_bgid;
        let mut result = Vec::with_capacity(count);
        let mut remaining = count;
        
        // Search through all block groups
        let mut groups_checked = 0;
        
        while remaining > 0 && groups_checked < block_group_count {
            // Load block group reference
            let mut block_group = 
                Ext4BlockGroup::load_new(self.block_device.clone(), super_block, bgid as usize);
            
            // Check if this group has free blocks
            let free_blocks = block_group.get_free_blocks_count();
            if free_blocks == 0 {
                log::debug!("[Block Alloc] Block group {} has no free blocks", bgid);
                bgid = (bgid + 1) % block_group_count;
                groups_checked += 1;
                continue;
            }
            
            // Get block bitmap for this group
            let bmp_blk_adr = block_group.get_block_bitmap_block(super_block);
            let mut bitmap_data = 
                self.block_device.read_offset(bmp_blk_adr as usize * BLOCK_SIZE);
            
            // Compute indexes and limits
            let first_in_bg = self.get_block_of_bgid(bgid);
            let first_in_bg_index = self.addr_to_idx_bg(first_in_bg);
            let idx_in_bg = first_in_bg_index; // Start from the beginning of the group
            let blocks_per_group = super_block.blocks_per_group();
            
            // Find free blocks in bitmap
            let mut found_blocks = 0;
            let max_to_find = core::cmp::min(remaining, free_blocks as usize);
            let mut rel_blk_idx = 0;
            let mut current_idx = idx_in_bg;
            
            // First try to find blocks in a simple loop starting from current_idx
            while found_blocks < max_to_find && current_idx < blocks_per_group {
                // Ensure we don't go beyond bitmap size (BLOCK_SIZE * 8 bits)
                if current_idx >= BLOCK_SIZE as u32 * 8 {
                    break;
                }
                
                if ext4_bmap_is_bit_clr(&bitmap_data, current_idx) {
                    // Found a free block
                    ext4_bmap_bit_set(&mut bitmap_data, current_idx);
                    
                    // Calculate physical block address
                    let block_num = self.bg_idx_to_addr(current_idx, bgid);
                    
                    // Add to result
                    result.push(block_num);
                    found_blocks += 1;
                    
                    // For debugging continuity issues
                    if result.len() > 1 {
                        let prev_block = result[result.len() - 2];
                        if block_num != prev_block + 1 {
                            log::debug!("[Block Alloc] Non-contiguous blocks: prev={}, current={}, diff={}",
                                prev_block, block_num, block_num - prev_block);
                        }
                    }
                }
                
                current_idx += 1;
            }
            
            // If we didn't find enough blocks using sequential search, use bitmap search function
            if found_blocks < max_to_find {
                let start_idx = current_idx;
                
                while found_blocks < max_to_find {
                    // Make sure we don't exceed the bitmap size
                    let end_idx = core::cmp::min(blocks_per_group, BLOCK_SIZE as u32 * 8);
                    
                    // Find next clear bit
                    if !ext4_bmap_bit_find_clr(&bitmap_data, start_idx, end_idx, &mut rel_blk_idx) {
                        break; // No more free blocks in this group
                    }
                    
                    ext4_bmap_bit_set(&mut bitmap_data, rel_blk_idx);
                    
                    // Calculate physical block address
                    let block_num = self.bg_idx_to_addr(rel_blk_idx, bgid);
                    
                    // Add to result
                    result.push(block_num);
                    found_blocks += 1;
                    
                    // For debugging continuity issues
                    if result.len() > 1 {
                        let prev_block = result[result.len() - 2];
                        if block_num != prev_block + 1 {
                            log::debug!("[Block Alloc] Non-contiguous blocks: prev={}, current={}, diff={}",
                                prev_block, block_num, block_num - prev_block);
                        }
                    }
                }
            }
            
            // If we found any blocks, update metadata
            if found_blocks > 0 {
                // Update bitmap on disk
                block_group.set_block_group_balloc_bitmap_csum(super_block, &bitmap_data);
                self.block_device.write_offset(bmp_blk_adr as usize * BLOCK_SIZE, &bitmap_data);
                
                // Update block group free blocks count
                let new_free_count = free_blocks - found_blocks as u64;
                block_group.set_free_blocks_count(new_free_count as u32);
                block_group.sync_to_disk_with_csum(self.block_device.clone(), bgid as usize, super_block);
                
                // Update superblock free blocks count
                let mut sb_copy = *super_block;
                let sb_free_blocks = sb_copy.free_blocks_count();
                sb_copy.set_free_blocks_count(sb_free_blocks - found_blocks as u64);
                sb_copy.sync_to_disk_with_csum(self.block_device.clone());
                
                // Update inode blocks count
                let blocks_per_fs_block = BLOCK_SIZE as u64 / EXT4_INODE_BLOCK_SIZE as u64;
                let mut inode_blocks = inode_ref.inode.blocks_count();
                inode_blocks += found_blocks as u64 * blocks_per_fs_block;
                inode_ref.inode.set_blocks_count(inode_blocks);
                
                // Decrement remaining blocks to allocate
                remaining -= found_blocks;
                
                log::info!("[Block Alloc] Allocated {} blocks from bg {}", found_blocks, bgid);
            }
            
            // Try next block group
            bgid = (bgid + 1) % block_group_count;
            groups_checked += 1;
        }
        
        // Log allocation results
        let allocated_count = result.len();
        log::info!("[Block Alloc] Allocated {}/{} blocks", allocated_count, count);
        
        // Even if we couldn't allocate all requested blocks, return what we got
        if remaining > 0 {
            log::warn!("[Block Alloc] Could only allocate {} out of {} blocks. Remaining: {}", 
                allocated_count, count, remaining);
        }
        
        // Update start_bgid to continue from where we left off next time
        *start_bgid = bgid;
        
        // Write back inode to save block count changes
        if allocated_count > 0 {
            self.write_back_inode(inode_ref);
        }
        
        Ok(result)
    }
}
