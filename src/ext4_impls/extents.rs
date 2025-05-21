use crate::prelude::*;
use crate::return_errno_with_message;
use crate::ext4_defs::*;
use alloc::format;


impl Ext4 {
    /// Find an extent in the extent tree.
    ///
    /// Params:
    /// inode_ref: &Ext4InodeRef - inode reference
    /// lblock: Ext4Lblk - logical block id
    ///
    /// Returns:
    /// `Result<SearchPath>` - search path
    ///
    /// 如果 depth > 0，则查找extent_index，查找目标 lblock 对应的 extent。
    /// 如果 depth = 0，则直接在root节点中查找 extent，查找目标 lblock 对应的 extent。
    pub fn find_extent(&self, inode_ref: &Ext4InodeRef, lblock: Ext4Lblk) -> Result<SearchPath> {
        let mut search_path = SearchPath::new();

        // Load the root node
        let root_data: &[u8; 60] =
            unsafe { core::mem::transmute::<&[u32; 15], &[u8; 60]>(&inode_ref.inode.block) };
        let mut node = ExtentNode::load_from_data(root_data, true).unwrap();

        let mut depth = node.header.depth;

        // Traverse down the tree if depth > 0
        let mut pblock_of_node = 0;
        while depth > 0 {
            let index_pos = node.binsearch_idx(lblock);
            if let Some(pos) = index_pos {
                let index = node.get_index(pos)?;
                let next_block = index.leaf_lo;

                search_path.path.push(ExtentPathNode {
                    header: node.header,
                    index: Some(index),
                    extent: None,
                    position: pos,
                    pblock: next_block as u64,
                    pblock_of_node,
                });

                let next_block = search_path.path.last().unwrap().index.unwrap().leaf_lo;
                let mut next_data = self
                    .block_device
                    .read_offset(next_block as usize * BLOCK_SIZE);
                node = ExtentNode::load_from_data_mut(&mut next_data, false)?;
                depth -= 1;
                search_path.depth += 1;
                pblock_of_node = next_block as usize;
            } else {
                return_errno_with_message!(Errno::ENOENT, "Extentindex not found");
            }
        }

        // Handle the case where depth is 0
        if let Some((extent, pos)) = node.binsearch_extent(lblock) {
            search_path.path.push(ExtentPathNode {
                header: node.header,
                index: None,
                extent: Some(extent),
                position: pos,
                pblock: lblock as u64 - extent.get_first_block() as u64 + extent.get_pblock(),
                pblock_of_node,
            });
            search_path.maxdepth = node.header.depth;

            Ok(search_path)
        } else {
            search_path.path.push(ExtentPathNode {
                header: node.header,
                index: None,
                extent: None,
                position: 0,
                pblock: 0,
                pblock_of_node,
            });
            Ok(search_path)
        }
    }

    /// Insert an extent into the extent tree.
    pub fn insert_extent(
        &self,
        inode_ref: &mut Ext4InodeRef,
        newex: &mut Ext4Extent,
    ) -> Result<()> {
        let newex_first_block = newex.first_block;
        log::info!("[insert_extent] Starting - Inserting extent at block {}", newex_first_block);
        log::info!("[insert_extent] Current tree state: magic={:x}, entries={}, max={}, depth={}", 
            inode_ref.inode.root_extent_header().magic,
            inode_ref.inode.root_extent_header().entries_count,
            inode_ref.inode.root_extent_header().max_entries_count,
            inode_ref.inode.root_extent_header().depth);
        
        let mut search_path = self.find_extent(inode_ref, newex_first_block)?;
        
        let depth = search_path.depth as usize;
        let node = &search_path.path[depth]; // Get the node at the current depth

        let at_root = node.pblock_of_node == 0;
        let header = node.header;

        // Node is empty (no extents)
        if header.entries_count == 0 {
            log::info!("[insert_extent] Node is empty, inserting directly");
            self.insert_new_extent(inode_ref, &mut search_path, newex)?;
            return Ok(());
        }

        // Insert to exsiting extent
        if let Some(mut ex) = node.extent {
            let pos = node.position;
            let last_extent_pos = header.entries_count as usize - 1;

            // Try to Insert to found_ext
            // found_ext:   |<---found_ext--->|         |<---ext2--->|
            //              20              30         50          60
            // insert:      |<---found_ext---><---newex--->|         |<---ext2--->|
            //              20              30            40         50          60
            // merge:       |<---newex--->|      |<---ext2--->|
            //              20           40      50          60
            if self.can_merge(&ex, newex) {
                self.merge_extent(&search_path, &mut ex, newex)?;

                if at_root {
                    // we are at root
                    *inode_ref.inode.root_extent_mut_at(node.position) = ex;
                }
                return Ok(());
            }

            // Insert right
            // found_ext:   |<---found_ext--->|         |<---next_extent--->|
            //              10               20         30                40
            // insert:      |<---found_ext--->|<---newex---><---next_extent--->|
            //              10               20            30                40
            // merge:       |<---found_ext--->|<---newex--->|
            //              10               20            40
            if pos < last_extent_pos
                && ((ex.first_block + ex.block_count as u32) < newex.first_block)
            {
                if let Ok(next_extent) = self.get_extent_from_node(node, pos + 1) {
                    if self.can_merge(&next_extent, newex) {
                        self.merge_extent(&search_path, newex, &next_extent)?;
                        return Ok(());
                    }
                }
            }

            // Insert left
            //  found_ext:  |<---found_ext--->|         |<---ext2--->|
            //              20              30         40          50
            // insert:   |<---prev_extent---><---newex--->|<---found_ext--->|....|<---ext2--->|
            //           0                  10          20                 30    40          50
            // merge:    |<---newex--->|<---found_ext--->|....|<---ext2--->|
            //           0            20                30    40          50
            if pos > 0 && (newex.first_block + newex.block_count as u32) < ex.first_block {
                if let Ok(mut prev_extent) = self.get_extent_from_node(node, pos - 1) {
                    if self.can_merge(&prev_extent, newex) {
                        self.merge_extent(&search_path, &mut prev_extent, newex)?;
                        return Ok(());
                    }
                }
            }
        }

        // Check if there's space to insert the new extent
        //                full         full
        // Before:   |<---ext1--->|<---ext2--->|
        //           10           20          30

        //                full          full
        // insert:   |<---ext1--->|<---ext2--->|<---newex--->|
        //           10           20           30           35
        if header.entries_count < header.max_entries_count {
            log::info!("[insert_extent] Node has space, inserting new extent");
            self.insert_new_extent(inode_ref, &mut search_path, newex)?;
        } else {
            log::info!("[insert_extent] Node is full (entries={}, max={}), creating new leaf", 
                header.entries_count, header.max_entries_count);
            self.create_new_leaf(inode_ref, &mut search_path, newex)?;
        }

        log::info!("[insert_extent] Completed - Final tree state: magic={:x}, entries={}, max={}, depth={}", 
            inode_ref.inode.root_extent_header().magic,
            inode_ref.inode.root_extent_header().entries_count,
            inode_ref.inode.root_extent_header().max_entries_count,
            inode_ref.inode.root_extent_header().depth);

        Ok(())
    }

    /// Get extent from the node at the given position.
    fn get_extent_from_node(&self, node: &ExtentPathNode, pos: usize) -> Result<Ext4Extent> {
        let data = self
            .block_device
            .read_offset(node.pblock as usize * BLOCK_SIZE);
        let extent_node = ExtentNode::load_from_data(&data, false).unwrap();

        match extent_node.get_extent(pos) {
            Some(extent) => Ok(extent),
            None => return_errno_with_message!(Errno::EINVAL, "Failed to get extent from node"),
        }
    }

    /// Get index from the node at the given position.
    fn get_index_from_node(&self, node: &ExtentPathNode, pos: usize) -> Result<Ext4ExtentIndex> {
        let data = self
            .block_device
            .read_offset(node.pblock as usize * BLOCK_SIZE);
        let extent_node = ExtentNode::load_from_data(&data, false).unwrap();

        extent_node.get_index(pos)
    }


    /// Check if two extents can be merged.
    ///
    /// This function determines whether two extents, `ex1` and `ex2`, can be merged
    /// into a single extent. Extents are contiguous ranges of blocks in the ext4
    /// filesystem that map logical block numbers to physical block numbers.
    ///
    /// # Arguments
    ///
    /// * `ex1` - The first extent to check.
    /// * `ex2` - The second extent to check.
    ///
    /// # Returns
    ///
    /// * `true` if the extents can be merged.
    /// * `false` otherwise.
    ///
    /// # Merge Conditions
    ///
    /// 1. **Same Unwritten State**:
    ///    - The `is_unwritten` state of both extents must be the same.
    ///    - Unwritten extents are placeholders for blocks that are allocated but not initialized.
    ///
    /// 2. **Contiguous Block Ranges**:
    ///    - The logical block range of the first extent must immediately precede
    ///      the logical block range of the second extent.
    ///
    /// 3. **Maximum Length**:
    ///    - The total length of the merged extent must not exceed the maximum allowed
    ///      extent length (`EXT_INIT_MAX_LEN`).
    ///    - If the extents are unwritten, the total length must also not exceed
    ///      the maximum length for unwritten extents (`EXT_UNWRITTEN_MAX_LEN`).
    ///
    /// 4. **Contiguous Physical Blocks**:
    ///    - The physical block range of the first extent must immediately precede
    ///      the physical block range of the second extent. This ensures that the
    ///      physical storage is contiguous.
    fn can_merge(&self, ex1: &Ext4Extent, ex2: &Ext4Extent) -> bool {
        // Check if the extents have the same unwritten state
        if ex1.is_unwritten() != ex2.is_unwritten() {
            return false;
        }
        let ext1_ee_len = ex1.get_actual_len() as usize;
        let ext2_ee_len = ex2.get_actual_len() as usize;
        
        // Check if the block ranges are contiguous
        if ex1.first_block + ext1_ee_len as u32 != ex2.first_block {
            return false;
        }

        // Check if the merged length would exceed the maximum allowed length
        if ext1_ee_len + ext2_ee_len > EXT_INIT_MAX_LEN as usize{
            return false;
        }

        // Check if the physical blocks are contiguous
        if ex1.get_pblock() + ext1_ee_len as u64 == ex2.get_pblock() {
            return true;
        }
        false
    }


    fn merge_extent(
        &self,
        search_path: &SearchPath,
        left_ext: &mut Ext4Extent,
        right_ext: &Ext4Extent,
    ) -> Result<()> {
        let depth = search_path.depth as usize;
        
        log::info!("[merge_extent] Merging extents at depth {}", depth);
        log::info!("[merge_extent] Left extent: logical block {}, physical block {}, length {}", 
            left_ext.first_block, left_ext.get_pblock(), left_ext.get_actual_len());
        log::info!("[merge_extent] Right extent: logical block {}, physical block {}, length {}", 
            right_ext.first_block, right_ext.get_pblock(), right_ext.get_actual_len());

        let unwritten = left_ext.is_unwritten();
        let len = left_ext.get_actual_len() + right_ext.get_actual_len();
        left_ext.set_actual_len(len);
        if unwritten {
            left_ext.mark_unwritten();
        }
        let header = search_path.path[depth].header;

        log::info!("[merge_extent] Merged extent: logical block {}, physical block {}, new length {}", 
            left_ext.first_block, left_ext.get_pblock(), left_ext.get_actual_len());

        if header.max_entries_count > 4 {
            let node = &search_path.path[depth];
            let block = node.pblock_of_node;
            let new_ex_offset = core::mem::size_of::<Ext4ExtentHeader>() + core::mem::size_of::<Ext4Extent>() * (node.position);
            let mut ext4block = Block::load(self.block_device.clone(), block * BLOCK_SIZE);
            let left_ext:&mut Ext4Extent = ext4block.read_offset_as_mut(new_ex_offset);

            let unwritten = left_ext.is_unwritten();
            let len = left_ext.get_actual_len() + right_ext.get_actual_len();
            left_ext.set_actual_len(len);
            if unwritten {
                left_ext.mark_unwritten();
            }

            log::info!("[merge_extent] Updated on-disk extent: logical block {}, physical block {}, length {}", 
                left_ext.first_block, left_ext.get_pblock(), left_ext.get_actual_len());

            ext4block.sync_blk_to_disk(self.block_device.clone());
            log::info!("[merge_extent] Synced merged extent to disk");
        }

        Ok(())
    }

    fn insert_new_extent(
        &self,
        inode_ref: &mut Ext4InodeRef,
        search_path: &mut SearchPath,
        new_extent: &mut Ext4Extent,
    ) -> Result<()> {
        let depth = search_path.depth as usize;
        let node = &mut search_path.path[depth]; // Get the node at the current depth
        let header = node.header;

        log::info!("[insert_new_extent] Inserting extent at depth {}: logical block {}, physical block {}, length {}", 
            depth, new_extent.first_block, new_extent.get_pblock(), new_extent.get_actual_len());
        log::info!("[insert_new_extent] Node info: entries={}, max={}, position={}", 
            header.entries_count, header.max_entries_count, node.position);
        
        log::debug!("[insert_new_extent] New extent details:");
        log::debug!("  - Logical start block: {}", new_extent.first_block);
        log::debug!("  - Physical start block: {}", new_extent.get_pblock());
        log::debug!("  - Block count: {}", new_extent.block_count);
        log::debug!("  - Actual length: {}", new_extent.get_actual_len());
        log::debug!("  - Unwritten: {}", new_extent.is_unwritten());
        log::debug!("  - Raw data: start_lo={}, start_hi={}, block_count={:#x}", 
            new_extent.start_lo, new_extent.start_hi, new_extent.block_count);
        log::debug!("  - Tree position: depth={}, position={}, at_root={}", 
            depth, node.position, node.pblock_of_node == 0);

        // insert at root
        if depth == 0 {
            // Node is empty (no extents)
            if header.entries_count == 0 {
                log::info!("[insert_new_extent] Inserting first extent into empty root node");
                *inode_ref.inode.root_extent_mut_at(node.position) = *new_extent;
                inode_ref.inode.root_extent_header_mut().entries_count += 1;

                self.write_back_inode(inode_ref);
                
                // 添加在根节点插入成功后的debug日志
                log::debug!("[insert_new_extent] Successfully inserted at root:");
                log::debug!("  - Root header: magic={:x}, entries={}, max={}, depth={}", 
                    inode_ref.inode.root_extent_header().magic,
                    inode_ref.inode.root_extent_header().entries_count,
                    inode_ref.inode.root_extent_header().max_entries_count,
                    inode_ref.inode.root_extent_header().depth);
                
                return Ok(());
            }
            // Check if root node is full, need to grow in depth
            if header.entries_count == header.max_entries_count {
                log::info!("[insert_new_extent] Root node full, growing in depth");
                self.ext_grow_indepth(inode_ref)?;
                // After growing, re-insert
                return self.insert_extent(inode_ref, new_extent);
            }

            
            // Not empty, insert at search result pos + 1
            log::info!("[insert_new_extent] Inserting at root at position {} (entries: {})", 
                node.position + 1, header.entries_count);
            *inode_ref.inode.root_extent_mut_at(node.position + 1) = *new_extent;
            inode_ref.inode.root_extent_header_mut().entries_count += 1;
            
            log::debug!("[insert_new_extent] Successfully inserted at root:");
            log::debug!("  - Root header: magic={:x}, entries={}, max={}, depth={}", 
                inode_ref.inode.root_extent_header().magic,
                inode_ref.inode.root_extent_header().entries_count,
                inode_ref.inode.root_extent_header().max_entries_count,
                inode_ref.inode.root_extent_header().depth);
            
            return Ok(());
        } else {
            // insert at nonroot
            log::info!("[insert_new_extent] Inserting at non-root node at depth {}, position {}", 
                depth, node.position + 1);

            // load block
            let node_block = node.pblock_of_node;
            let mut ext4block =
            Block::load(self.block_device.clone(), node_block * BLOCK_SIZE);
            let new_ex_offset = core::mem::size_of::<Ext4ExtentHeader>() + core::mem::size_of::<Ext4Extent>() * (node.position + 1);

            // insert new extent
            let ex: &mut Ext4Extent = ext4block.read_offset_as_mut(new_ex_offset);
            *ex = *new_extent;
            let header: &mut Ext4ExtentHeader = ext4block.read_offset_as_mut(0);

            // update entry count 
            header.entries_count += 1;
            log::info!("[insert_new_extent] Updated non-root node: entries={}, max={}", 
                header.entries_count, header.max_entries_count);

            // 先完成块的处理并同步到磁盘
            let node_header_entries = header.entries_count;
            let node_header_max = header.max_entries_count;
            ext4block.sync_blk_to_disk(self.block_device.clone());
            log::info!("[insert_new_extent] Synced non-root node to disk");

            log::debug!("[insert_new_extent] Successfully inserted at non-root node:");
            log::debug!("  - Node header: entries={}, max={}, depth={}", 
                node_header_entries, node_header_max, depth);
            log::debug!("  - Block address: {}", node_block);
            log::debug!("  - Extent position: {}", node.position + 1);
            log::debug!("  - Extent: logical={}, physical={}, length={}", 
                new_extent.first_block, new_extent.get_pblock(), new_extent.get_actual_len());

            return Ok(());
        }

        return_errno_with_message!(Errno::ENOTSUP, "Not supported insert extent at nonroot");
    }

    // finds empty index and adds new leaf. if no free index is found, then it requests in-depth growing.
    fn create_new_leaf(
        &self,
        inode_ref: &mut Ext4InodeRef,
        search_path: &mut SearchPath,
        new_extent: &mut Ext4Extent,
    ) -> Result<()> {
        log::info!("[create_new_leaf] Starting - Current tree state:");
        log::info!("[create_new_leaf] Root header: magic={:x}, entries={}, max={}, depth={}", 
            inode_ref.inode.root_extent_header().magic,
            inode_ref.inode.root_extent_header().entries_count,
            inode_ref.inode.root_extent_header().max_entries_count,
            inode_ref.inode.root_extent_header().depth);
        log::info!("[create_new_leaf] New extent: logical block {}, physical block {}, length {}", 
            new_extent.first_block, new_extent.get_pblock(), new_extent.get_actual_len());
        
        // tree is full, time to grow in depth
        log::info!("[create_new_leaf] Tree is full, calling ext_grow_indepth");
        self.ext_grow_indepth(inode_ref)?;
        
        log::info!("[create_new_leaf] After ext_grow_indepth - New tree state:");
        log::info!("[create_new_leaf] Root header: magic={:x}, entries={}, max={}, depth={}", 
            inode_ref.inode.root_extent_header().magic,
            inode_ref.inode.root_extent_header().entries_count,
            inode_ref.inode.root_extent_header().max_entries_count,
            inode_ref.inode.root_extent_header().depth);

        // insert again
        log::info!("[create_new_leaf] Attempting to insert extent again");
        self.insert_extent(inode_ref, new_extent)
    }

    
    // allocates new block
    // moves top-level data (index block or leaf) into the new block
    // initializes new top-level, creating index that points to the
    // just created block
    fn ext_grow_indepth(&self, inode_ref: &mut Ext4InodeRef) -> Result<()>{
        log::info!("[ext_grow_indepth] Starting - Current tree state:");
        log::info!("[ext_grow_indepth] Root header: magic={:x}, entries={}, max={}, depth={}", 
            inode_ref.inode.root_extent_header().magic,
            inode_ref.inode.root_extent_header().entries_count,
            inode_ref.inode.root_extent_header().max_entries_count,
            inode_ref.inode.root_extent_header().depth);

        // 分配新块用于存储原始根节点内容
        let new_block = self.balloc_alloc_block(inode_ref, None)?;
        log::info!("[ext_grow_indepth] Allocated new block: {}", new_block);

        // 加载新块
        let mut new_ext4block =
            Block::load(self.block_device.clone(), new_block as usize * BLOCK_SIZE);
        log::info!("[ext_grow_indepth] Loaded new block");

        // 清空新块，确保没有垃圾数据
        new_ext4block.data.fill(0);

        // 保存原始根节点信息
        let old_root_header = inode_ref.inode.root_extent_header();
        let old_depth = old_root_header.depth;
        let old_entries_count = old_root_header.entries_count;
        
        // 获取第一个extent的逻辑块号(仅当原来是叶节点时)
        let first_logical_block = if old_depth == 0 && old_entries_count > 0 {
            inode_ref.inode.root_extent_at(0).first_block
        } else {
            0
        };

        // 复制根节点extents数据到新块
        // inode block中的extent开始位置为12字节(header之后)
        // 新块中的extent开始位置也是12字节(header之后)
        let header_size = EXT4_EXTENT_HEADER_SIZE;
        
        // 先复制header
        let mut new_header = Ext4ExtentHeader::new(
            EXT4_EXTENT_MAGIC,
            old_entries_count,
            ((BLOCK_SIZE - header_size) / EXT4_EXTENT_SIZE) as u16, // 新块可容纳的最大条目数
            0, // 新块变成叶节点，深度为0
            0  // generation字段，通常为0
        );
        
        // 将header写入新块
        let header_bytes = unsafe {
            core::slice::from_raw_parts(
                &new_header as *const _ as *const u8,
                header_size
            )
        };
        new_ext4block.data[..header_size].copy_from_slice(header_bytes);
        
        // 复制extents数据
        if old_entries_count > 0 {
            // 从root block复制extents到新块
            // inode block中的extent开始位置为12字节(header之后)
            // 新块中的extent开始位置也是12字节(header之后)
            let root_extents_size = old_entries_count as usize * EXT4_EXTENT_SIZE;
            
            // 使用临时变量存储block数据，避免可变借用冲突
            let block_data = unsafe {
                let block_ptr = inode_ref.inode.block.as_ptr();
                core::slice::from_raw_parts(block_ptr as *const u8, 60)
            };
            
            let root_extents_bytes = &block_data[header_size..header_size + root_extents_size];
            new_ext4block.data[header_size..header_size + root_extents_size]
                .copy_from_slice(root_extents_bytes);
        }
        
        log::info!("[ext_grow_indepth] Copied root data to new block and set header: magic={:x}, entries={}, max_entries={}, depth={}",
            new_header.magic, new_header.entries_count, new_header.max_entries_count, new_header.depth);
        
        // 同步新块到磁盘
        new_ext4block.sync_blk_to_disk(self.block_device.clone());
        log::info!("[ext_grow_indepth] Synced new block with extents to disk");
        
        // 先读取第一个extent的块号（如果有），然后更新root节点
        let first_logical_block_saved = first_logical_block;
        
        // 更新根节点为索引节点
        {
            let mut root_header = inode_ref.inode.root_extent_header_mut();
            root_header.set_magic(); // 设置magic
            root_header.set_entries_count(1); // 索引节点初始只有一个条目
            root_header.set_max_entries_count(4); // 根索引节点通常有4个条目
            root_header.add_depth(); // 增加深度
            
            log::info!("[ext_grow_indepth] Updated root header: depth {} -> {}, entries={}, max={}", 
                old_depth, root_header.depth, root_header.entries_count, root_header.max_entries_count);
        }
        
        // 清除原root节点中的extents数据
        unsafe {
            let root_block_ptr = inode_ref.inode.block.as_mut_ptr() as *mut u8;
            // 跳过header部分，只清除后面的extent数据
            let extents_ptr = root_block_ptr.add(header_size);
            core::ptr::write_bytes(extents_ptr, 0, 60 - header_size);
        }
        
        // 创建根节点的第一个索引条目指向新块
        {
            let mut root_first_index = inode_ref.inode.root_first_index_mut();
            root_first_index.first_block = first_logical_block_saved; // 设置起始逻辑块号
            root_first_index.store_pblock(new_block); // 存储新块的物理地址
            
            log::info!("[ext_grow_indepth] Root became index block, first_block={}, pointing to block {}", 
                first_logical_block_saved, new_block);
        }

        // 将更新后的inode写回磁盘
        self.write_back_inode(inode_ref);
        log::info!("[ext_grow_indepth] Wrote updated inode back to disk");

        log::info!("[ext_grow_indepth] Completed - Final tree state:");
        log::info!("[ext_grow_indepth] Root header: magic={:x}, entries={}, max={}, depth={}", 
            inode_ref.inode.root_extent_header().magic,
            inode_ref.inode.root_extent_header().entries_count,
            inode_ref.inode.root_extent_header().max_entries_count,
            inode_ref.inode.root_extent_header().depth);

        Ok(())
    }
}

impl Ext4 {
    // Assuming init state
    // depth 0 (root node)
    // +--------+--------+--------+
    // |  idx1  |  idx2  |  idx3  |
    // +--------+--------+--------+
    //     |         |         |
    //     v         v         v
    //
    // depth 1 (internal node)
    // +--------+...+--------+  +--------+...+--------+ ......
    // |  idx1  |...|  idxn  |  |  idx1  |...|  idxn  | ......
    // +--------+...+--------+  +--------+...+--------+ ......
    //     |           |         |             |
    //     v           v         v             v
    //
    // depth 2 (leaf nodes)
    // +--------+...+--------+  +--------+...+--------+  ......
    // | ext1   |...| extn   |  | ext1   |...| extn   |  ......
    // +--------+...+--------+  +--------+...+--------+  ......
    pub fn extent_remove_space(
        &self,
        inode_ref: &mut Ext4InodeRef,
        from: u32,
        to: u32,
    ) -> Result<usize> {
        // log::info!("Remove space from {:x?} to {:x?}", from, to);
        let mut search_path = self.find_extent(inode_ref, from)?;

        // for i in search_path.path.iter() {
        //     log::info!("from Path: {:x?}", i);
        // }

        let depth = search_path.depth as usize;

        /* If we do remove_space inside the range of an extent */
        let mut ex = search_path.path[depth].extent.unwrap();
        if ex.get_first_block() < from
            && to < (ex.get_first_block() + ex.get_actual_len() as u32 - 1)
        {
            let mut newex = Ext4Extent::default();
            let unwritten = ex.is_unwritten();
            let ee_block = ex.first_block;
            let block_count = ex.block_count;
            let newblock = to + 1 - ee_block + ex.get_pblock() as u32;
            ex.block_count = from as u16 - ee_block as u16;

            if unwritten {
                ex.mark_unwritten();
            }
            newex.first_block = to + 1;
            newex.block_count = (ee_block + block_count as u32 - 1 - to) as u16;
            newex.start_lo = newblock;
            newex.start_hi = ((newblock as u64) >> 32) as u16;

            self.insert_extent(inode_ref, &mut newex)?;

            return Ok(EOK);
        }

        // log::warn!("Remove space in depth: {:x?}", depth);

        let mut i = depth as isize;

        while i >= 0 {
            // we are at the leaf node
            // depth 0 (root node)
            // +--------+--------+--------+
            // |  idx1  |  idx2  |  idx3  |
            // +--------+--------+--------+
            //              |path
            //              v
            //              idx2
            // depth 1 (internal node)
            // +--------+--------+--------+ ......
            // |  idx1  |  idx2  |  idx3  | ......
            // +--------+--------+--------+ ......
            //              |path
            //              v
            //              ext2
            // depth 2 (leaf nodes)
            // +--------+--------+..+--------+
            // | ext1   | ext2   |..|last_ext|
            // +--------+--------+..+--------+
            //            ^            ^
            //            |            |
            //            from         to(exceed last ext, rest of the extents will be removed)
            if i as usize == depth {
                let node_pblock = search_path.path[i as usize].pblock_of_node;

                let header = search_path.path[i as usize].header;
                let entries_count = header.entries_count;

                // we are at root
                if node_pblock == 0 {
                    let first_ex = inode_ref.inode.root_extent_at(0);
                    let last_ex = inode_ref.inode.root_extent_at(entries_count as usize - 1);

                    let mut leaf_from = first_ex.first_block;
                    let mut leaf_to = last_ex.first_block + last_ex.get_actual_len() as u32 - 1;
                    if leaf_from < from {
                        leaf_from = from;
                    }
                    if leaf_to > to {
                        leaf_to = to;
                    }
                    // log::trace!("from {:x?} to {:x?} leaf_from {:x?} leaf_to {:x?}", from, to, leaf_from, leaf_to);
                    self.ext_remove_leaf(inode_ref, &mut search_path, leaf_from, leaf_to)?;

                    i -= 1;
                    continue;
                }
                let ext4block =
                    Block::load(self.block_device.clone(), node_pblock * BLOCK_SIZE);

                let header = search_path.path[i as usize].header;
                let entries_count = header.entries_count;

                let first_ex: Ext4Extent = ext4block.read_offset_as(size_of::<Ext4ExtentHeader>());
                let last_ex: Ext4Extent = ext4block.read_offset_as(
                    size_of::<Ext4ExtentHeader>()
                        + size_of::<Ext4Extent>() * (entries_count - 1) as usize,
                );

                let mut leaf_from = first_ex.first_block;
                let mut leaf_to = last_ex.first_block + last_ex.get_actual_len() as u32 - 1;

                if leaf_from < from {
                    leaf_from = from;
                }
                if leaf_to > to {
                    leaf_to = to;
                }
                // log::trace!(
                //     "from {:x?} to {:x?} leaf_from {:x?} leaf_to {:x?}",
                //     from,
                //     to,
                //     leaf_from,
                //     leaf_to
                // );

                self.ext_remove_leaf(inode_ref, &mut search_path, leaf_from, leaf_to)?;

                i -= 1;
                continue;
            }

            // log::trace!("---at level---{:?}\n", i);

            // we are at index
            // example i=1, depth=2
            // depth 0 (root node) - 处理的索引节点
            // +--------+--------+--------+
            // |  idx1  |  idx2  |  idx3  |
            // +--------+--------+--------+
            //            |path     | 下一个要处理的节点(more_to_rm?)
            //            v         v
            //           idx2
            //
            // depth 1 (internal node)
            // +--------++--------+...+--------+
            // |  idx1  ||  idx2  |...|  idxn  |
            // +--------++--------+...+--------+
            //            |path
            //            v
            //            ext2
            // depth 2 (leaf nodes)
            // +--------+--------+..+--------+
            // | ext1   | ext2   |..|last_ext|
            // +--------+--------+..+--------+
            let header = search_path.path[i as usize].header;
            if self.more_to_rm(&search_path.path[i as usize], to) {
                // todo
                // load next idx

                // go to this node's child
                i += 1;
            } else {
                if i > 0 {
                    // empty
                    if header.entries_count == 0 {
                        self.ext_remove_idx(inode_ref, &mut search_path, i as u16 - 1)?;
                    }
                }

                let idx = i;
                if idx - 1 < 0 {
                    break;
                }
                i -= 1;
            }
        }

        Ok(EOK)
    }

    pub fn ext_remove_leaf(
        &self,
        inode_ref: &mut Ext4InodeRef,
        path: &mut SearchPath,
        from: u32,
        to: u32,
    ) -> Result<usize> {
        // log::trace!("Remove leaf from {:x?} to {:x?}", from, to);

        // depth 0 (root node)
        // +--------+--------+--------+
        // |  idx1  |  idx2  |  idx3  |
        // +--------+--------+--------+
        //     |         |         |
        //     v         v         v
        //     ^
        //     Current position
        let depth = inode_ref.inode.root_header_depth();
        let mut header = path.path[depth as usize].header;

        let mut new_entry_count = header.entries_count;
        let mut ex2 = Ext4Extent::default();

        /* find where to start removing */
        let pos = path.path[depth as usize].position;
        let entry_count = header.entries_count;

        // depth 1 (internal node)
        // +--------+...+--------+  +--------+...+--------+ ......
        // |  idx1  |...|  idxn  |  |  idx1  |...|  idxn  | ......
        // +--------+...+--------+  +--------+...+--------+ ......
        //     |           |         |             |
        //     v           v         v             v
        //     ^
        //     Current loaded node

        // load node data
        let node_disk_pos = path.path[depth as usize].pblock_of_node * BLOCK_SIZE;

        let mut ext4block = if node_disk_pos == 0 {
            // we are at root
            Block::load_inode_root_block(&inode_ref.inode.block)
        } else {
            Block::load(self.block_device.clone(), node_disk_pos)
        };

        // depth 2 (leaf nodes)
        // +--------+...+--------+  +--------+...+--------+  ......
        // | ext1   |...| extn   |  | ext1   |...| extn   |  ......
        // +--------+...+--------+  +--------+...+--------+  ......
        //     ^
        //     Current start extent

        // start from pos
        for i in pos..entry_count as usize {
            let ex: &mut Ext4Extent = ext4block
                .read_offset_as_mut(size_of::<Ext4ExtentHeader>() + i * size_of::<Ext4Extent>());

            if ex.first_block > to {
                break;
            }

            let mut new_len = 0;
            let mut start = ex.first_block;
            let mut new_start = ex.first_block;

            let mut len = ex.get_actual_len();
            let mut newblock = ex.get_pblock();

            // Initial state:
            // +--------+...+--------+  +--------+...+--------+  ......
            // | ext1   |...| ext2   |  | ext3   |...| extn   |  ......
            // +--------+...+--------+  +--------+...+--------+  ......
            //               ^                    ^
            //              from                  to

            // Case 1: Remove a portion within the extent
            if start < from {
                len -= from as u16 - start as u16;
                new_len = from - start;
                start = from;
            } else {
                // Case 2: Adjust extent that partially overlaps the 'to' boundary
                if start + len as u32 - 1 > to {
                    new_len = start + len as u32 - 1 - to;
                    len -= new_len as u16;
                    new_start = to + 1;
                    newblock += (to + 1 - start) as u64;
                    ex2 = *ex;
                }
            }

            // After removing range from `from` to `to`:
            // +--------+...+--------+  +--------+...+--------+  ......
            // | ext1   |...[removed]|  |[removed]|...| extn   |  ......
            // +--------+...+--------+  +--------+...+--------+  ......
            //               ^                    ^
            //              from                  to
            //                                  new_start

            // Remove blocks within the extent
            self.ext_remove_blocks(inode_ref, ex, start, start + len as u32 - 1);

            ex.first_block = new_start;
            // log::trace!("after remove leaf ex first_block {:x?}", ex.first_block);

            if new_len == 0 {
                new_entry_count -= 1;
            } else {
                let unwritten = ex.is_unwritten();
                ex.store_pblock(newblock as u64);
                ex.block_count = new_len as u16;

                if unwritten {
                    ex.mark_unwritten();
                }
            }
        }

        // Move remaining extents to the start:
        // Before:
        // +--------+--------+...+--------+
        // | ext3   | ext4   |...| extn   |
        // +--------+--------+...+--------+
        //      ^       ^
        //      rm      rm
        // After:
        // +--------+.+--------+--------+...
        // | ext1   |.| extn   | [empty]|...
        // +--------+.+--------+--------+...

        // Move any remaining extents to the starting position of the node.
        if ex2.first_block > 0 {
            let start_index = size_of::<Ext4ExtentHeader>() + pos * size_of::<Ext4Extent>();
            let end_index =
                size_of::<Ext4ExtentHeader>() + entry_count as usize * size_of::<Ext4Extent>();
            let remaining_extents: Vec<u8> = ext4block.data[start_index..end_index].to_vec();
            ext4block.data[size_of::<Ext4ExtentHeader>()
                ..size_of::<Ext4ExtentHeader>() + remaining_extents.len()]
                .copy_from_slice(&remaining_extents);
        }

        // Update the entries count in the header
        header.entries_count = new_entry_count;

        /*
         * If the extent pointer is pointed to the first extent of the node, and
         * there's still extents presenting, we may need to correct the indexes
         * of the paths.
         */
        if pos == 0 && new_entry_count > 0 {
            self.ext_correct_indexes(path)?;
        }

        /* if this leaf is free, then we should
         * remove it from index block above */
        if new_entry_count == 0 {
            // if we are at root?
            if path.path[depth as usize].pblock_of_node == 0 {
                return Ok(EOK);
            }
            self.ext_remove_idx(inode_ref, path, depth - 1)?;
        } else if depth > 0 {
            // go to next index
            path.path[depth as usize - 1].position += 1;
        }

        Ok(EOK)
    }

    fn ext_remove_index_block(&self, inode_ref: &mut Ext4InodeRef, index: &mut Ext4ExtentIndex) {
        let block_to_free = index.get_pblock();

        // log::trace!("remove index's block {:x?}", block_to_free);
        self.balloc_free_blocks(inode_ref, block_to_free as _, 1);
    }

    fn ext_remove_idx(
        &self,
        inode_ref: &mut Ext4InodeRef,
        path: &mut SearchPath,
        depth: u16,
    ) -> Result<usize> {
        // log::trace!("Remove index at depth {:x?}", depth);

        // Initial state:
        // +--------+--------+--------+
        // |  idx1  |  idx2  |  idx3  |
        // +--------+--------+--------+
        //           ^
        // Current index to remove (pos=1)

        // Removing index:
        // +--------+--------+--------+
        // |  idx1  |[empty] |  idx3  |
        // +--------+--------+--------+
        //           ^
        // Current index to remove

        // After moving remaining indexes:
        // +--------+--------+--------+
        // |  idx1  |  idx3  |[empty] |
        // +--------+--------+--------+
        //           ^
        // Current index to remove

        let mut i = depth as usize;
        let mut header = path.path[i].header;

        // 获取要删除的索引块
        let leaf_block = path.path[i].index.unwrap().get_pblock();

        // 如果当前索引不是最后一个索引，将后续的索引前移
        if path.path[i].position != header.entries_count as usize - 1 {
            let start_pos = size_of::<Ext4ExtentHeader>()
                + path.path[i].position * size_of::<Ext4ExtentIndex>();
            let end_pos = size_of::<Ext4ExtentHeader>()
                + (header.entries_count as usize) * size_of::<Ext4ExtentIndex>();

            let node_disk_pos = path.path[i].pblock_of_node * BLOCK_SIZE;
            let mut ext4block = Block::load(self.block_device.clone(), node_disk_pos);

            let remaining_indexes: Vec<u8> =
                ext4block.data[start_pos + size_of::<Ext4ExtentIndex>()..end_pos].to_vec();
            ext4block.data[start_pos..start_pos + remaining_indexes.len()]
                .copy_from_slice(&remaining_indexes);
            let remaining_size = remaining_indexes.len();

            // 清空剩余位置
            let empty_start = start_pos + remaining_size;
            let empty_end = end_pos;
            ext4block.data[empty_start..empty_end].fill(0);
        }

        // 更新头部的entries_count
        header.entries_count -= 1;

        // 释放索引块
        self.ext_remove_index_block(inode_ref, &mut path.path[i].index.unwrap());

        // Updating parent index if necessary:
        // +--------+--------+--------+
        // |  idx1  |  idx3  |[empty] |
        // +--------+--------+--------+
        //           ^
        // Updated parent index if necessary

        // 如果当前层不是根，需要检查是否需要更新父节点索引
        while i > 0 {
            if path.path[i].position != 0 {
                break;
            }

            let parent_idx = i - 1;
            let parent_index = &mut path.path[parent_idx].index.unwrap();
            let current_index = &path.path[i].index.unwrap();

            parent_index.first_block = current_index.first_block;
            self.write_back_inode(inode_ref);

            i -= 1;
        }

        Ok(EOK)
    }

    /// Correct the first block of the parent index.
    fn ext_correct_indexes(&self, path: &mut SearchPath) -> Result<usize> {
        // if child get removed from parent, we need to update the parent's first_block
        let mut depth = path.depth as usize;

        // depth 2:
        // +--------+--------+--------+
        // |[empty] |  ext2  |  ext3  |
        // +--------+--------+--------+
        // ^
        // pos=0, ext1_first_block=0(removed) parent index first block=0

        // depth 2:
        // +--------+--------+--------+
        // |  ext2  |  ext3  |[empty] |
        // +--------+--------+--------+
        // ^
        // pos=0, now first_block=ext2_first_block

        // 更新父节点索引：
        // depth 1:
        // +-----------------------+
        // | idx1_2 |...| idx1_n   |
        // +-----------------------+
        //     ^
        //     更新父节点索引(first_block)

        // depth 0:
        // +--------+--------+--------+
        // |  idx1  |  idx2  |  idx3  |
        // +--------+--------+--------+
        //     |
        //     更新根节点索引(first_block)

        while depth > 0 {
            let parent_idx = depth - 1;

            // 获取当前层的 extent
            if let Some(child_extent) = path.path[depth].extent {
                // 获取父节点
                let parent_node = &mut path.path[parent_idx];
                // 获取父节点的索引，并更新 first_block
                if let Some(ref mut parent_index) = parent_node.index {
                    parent_index.first_block = child_extent.first_block;
                }
            }

            depth -= 1;
        }

        Ok(EOK)
    }

    fn ext_remove_blocks(
        &self,
        inode_ref: &mut Ext4InodeRef,
        ex: &mut Ext4Extent,
        from: u32,
        to: u32,
    ) {
        let len = to - from + 1;
        let num = from - ex.first_block;
        let start: u32 = ex.get_pblock() as u32 + num;
        self.balloc_free_blocks(inode_ref, start as _, len);
    }

    pub fn more_to_rm(&self, path: &ExtentPathNode, to: u32) -> bool {
        let header = path.header;

        // No Sibling exists
        if header.entries_count == 1 {
            return false;
        }

        let pos = path.position;
        if pos > header.entries_count as usize - 1 {
            return false;
        }

        // Check if index is out of bounds
        if let Some(index) = path.index {
            let last_index_pos = header.entries_count as usize - 1;
            let node_disk_pos = path.pblock_of_node * BLOCK_SIZE;
            let ext4block = Block::load(self.block_device.clone(), node_disk_pos);
            let last_index: Ext4ExtentIndex =
                ext4block.read_offset_as(size_of::<Ext4ExtentIndex>() * last_index_pos);

            if path.position > last_index_pos || index.first_block > last_index.first_block {
                return false;
            }

            // Check if index's first_block is greater than 'to'
            if index.first_block > to {
                return false;
            }
        }

        true
    }
}
