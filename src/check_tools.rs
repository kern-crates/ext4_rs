use crate::prelude::*;
use crate::ext4_defs::*;
use crate::ext4_impls::*;

#[derive(Debug, Clone)]
pub struct SystemZone {
    group: u32,
    start_blk: u64,
    end_blk: u64,
    count: u64,
    ino: u32,
    reason: &'static str,
}

fn collect_system_zones(ext4: &Ext4) -> Vec<SystemZone> {
    let mut zones = Vec::new();
    let group_count = ext4.super_block.block_group_count();
    let blocks_per_group = ext4.super_block.blocks_per_group();
    let inodes_per_group = ext4.super_block.inodes_per_group();
    let inode_size = ext4.super_block.inode_size() as u64;
    let block_size = ext4.super_block.block_size() as u64;
    let desc_size = ext4.super_block.desc_size();
    let block_device = ext4.block_device.clone();
    let super_block = &ext4.super_block;

    for bgid in 0..group_count {
        // 0. meta blocks
        let meta_blks = ext4.num_base_meta_blocks(bgid);
        if meta_blks != 0 {
            let start = ext4.get_block_of_bgid(bgid);
            zones.push(SystemZone {
                group: bgid,
                start_blk: start,
                end_blk: start + meta_blks as u64 - 1,
                count: meta_blks as u64,
                ino: 0,
                reason: "meta",
            });
        }
        // 加载block group描述符
        let block_group = Ext4BlockGroup::load_new(block_device.clone(), super_block, bgid as usize);
        // 1. block bitmap
        let blk_bmp = block_group.get_block_bitmap_block(super_block);
        zones.push(SystemZone {
            group: bgid,
            start_blk: blk_bmp,
            end_blk: blk_bmp,
            count: 1,
            ino: 0,
            reason: "block_bitmap",
        });
        // 2. inode bitmap
        let ino_bmp = block_group.get_inode_bitmap_block(super_block);
        zones.push(SystemZone {
            group: bgid,
            start_blk: ino_bmp,
            end_blk: ino_bmp,
            count: 1,
            ino: 0,
            reason: "inode_bitmap",
        });
        // 3. inode table
        let ino_tbl = block_group.get_inode_table_blk_num() as u64;
        let itb_per_group = ((inodes_per_group as u64 * inode_size + block_size - 1) / block_size) as u64;
        zones.push(SystemZone {
            group: bgid,
            start_blk: ino_tbl,
            end_blk: ino_tbl + itb_per_group - 1,
            count: itb_per_group,
            ino: 0,
            reason: "inode_table",
        });
    }
    zones
}

pub fn get_system_zones(ext4: &Ext4) -> Vec<SystemZone> {
    let zones = collect_system_zones(ext4);
    for z in &zones {
        log::trace!(
            "system_zone: group={} start_blk={} end_blk={} count={} ino={} [{}]",
            z.group, z.start_blk, z.end_blk, z.count, z.ino, z.reason
        );
    }
    zones
}

pub fn check_inode_extents(ext4: &Ext4, inode_num: u32, system_zones: &Vec<SystemZone>) {
    let inode_ref = ext4.get_inode_ref(inode_num);
    let eh = inode_ref.inode.root_extent_header();
    log::trace!("inode {} extent header: magic={:#x}, entries={}, max={}, depth={}", inode_num, eh.magic, eh.entries_count, eh.max_entries_count, eh.depth);
    fn print_node(ext4: &Ext4, inode_ref: &Ext4InodeRef, eh: &Ext4ExtentHeader, depth: u16, pblk: u64, system_zones: &Vec<SystemZone>) {
        if depth == 0 {
            let mut node_data = if pblk == 0 {
                unsafe {
                    let block_ptr = inode_ref.inode.block.as_ptr();
                    let data = core::slice::from_raw_parts(block_ptr as *const u8, 60);
                    data.to_vec()
                }
            } else {
                ext4.block_device.read_offset(pblk as usize * BLOCK_SIZE)
            };
            let entries = eh.entries_count as usize;
            for i in 0..entries {
                let ex_offset = core::mem::size_of::<Ext4ExtentHeader>() + i * core::mem::size_of::<Ext4Extent>();
                let ex = unsafe { &*(node_data[ex_offset..].as_ptr() as *const Ext4Extent) };
                let pblock = ex.get_pblock();
                let ext_start = pblock;
                let ext_end = pblock + ex.get_actual_len() as u64 - 1;
                log::trace!("  extent: first_block={} block_count={} pblock={}..{} (len={})", ex.first_block, ex.get_actual_len(), pblock, ext_end, ex.get_actual_len());
                for zone in system_zones {
                    if ext_start <= zone.end_blk && ext_end >= zone.start_blk {
                        log::trace!(
                            "!!! OVERLAP system zone: extent first_block={} pblock={}..{} (len={}) with system_zone group={} start_blk={} end_blk={} [{}]",
                            ex.first_block, ext_start, ext_end, ex.get_actual_len(),
                            zone.group, zone.start_blk, zone.end_blk, zone.reason
                        );
                    }
                }
                for iblock in ex.first_block..ex.first_block + ex.get_actual_len() as u32 {
                    let pblock = ext4.get_pblock_idx(&inode_ref, iblock).unwrap();
                    for zone in system_zones {
                        if pblock >= zone.start_blk && pblock <= zone.end_blk {
                            log::trace!(
                                "!!! LOGICAL BLOCK {} maps to SYSTEM ZONE pblock {} (extent first_block={}, len={}) with system_zone group={} start_blk={} end_blk={} [{}]",
                                iblock, pblock, ex.first_block, ex.get_actual_len(),
                                zone.group, zone.start_blk, zone.end_blk, zone.reason
                            );
                        }
                    }
                }
            }
        } else {
            let mut node_data = if pblk == 0 {
                unsafe {
                    let block_ptr = inode_ref.inode.block.as_ptr();
                    let data = core::slice::from_raw_parts(block_ptr as *const u8, 60);
                    data.to_vec()
                }
            } else {
                ext4.block_device.read_offset(pblk as usize * BLOCK_SIZE)
            };
            let entries = eh.entries_count as usize;
            for i in 0..entries {
                let idx_offset = core::mem::size_of::<Ext4ExtentHeader>() + i * core::mem::size_of::<Ext4ExtentIndex>();
                let idx = unsafe { &*(node_data[idx_offset..].as_ptr() as *const Ext4ExtentIndex) };
                let child_pblk = idx.get_pblock();
                log::trace!("  index: first_block={} -> pblk={} (subtree)", idx.first_block, child_pblk);
                for zone in system_zones {
                    if child_pblk >= zone.start_blk && child_pblk <= zone.end_blk {
                        log::trace!(
                            "!!! OVERLAP system zone: INDEX first_block={} -> pblk={} 命中 system zone group={} start_blk={} end_blk={} [{}]",
                            idx.first_block, child_pblk, zone.group, zone.start_blk, zone.end_blk, zone.reason
                        );
                    }
                }
                let child_eh = if child_pblk == 0 {
                    inode_ref.inode.root_extent_header()
                } else {
                    let data = ext4.block_device.read_offset(child_pblk as usize * BLOCK_SIZE);
                    Ext4ExtentHeader::load_from_u8(&data[..core::mem::size_of::<Ext4ExtentHeader>()])
                };
                print_node(ext4, inode_ref, &child_eh, depth - 1, child_pblk, system_zones);
            }
        }
    }
    print_node(ext4, &inode_ref, &eh, eh.depth, 0, system_zones);
}


fn test_raw_block_device_write(block_device: Arc<dyn BlockDevice>, size_mb: usize) {
    let write_size = size_mb * 1024 * 1024;
    let mut buffer = vec![0x41u8; write_size];

    // Start from block 1000 to avoid overwriting important data
    let start_block = 1000;
    let start_offset = start_block * BLOCK_SIZE;

    log::info!("Starting raw BlockDevice write test: {} MB", size_mb);
    let start_time = std::time::Instant::now();

    // Write in BLOCK_SIZE chunks
    let mut written = 0;
    while written < write_size {
        let write_size = std::cmp::min(BLOCK_SIZE, write_size - written);
        let offset = start_offset + written;
        block_device.write_offset(offset, &buffer[written..written + write_size]);
        written += write_size;
    }

    let end_time = start_time.elapsed();
    let speed_mb_per_sec = (write_size as f64 / 1024.0 / 1024.0) / end_time.as_secs_f64();

    log::info!("Raw BlockDevice write speed: {:.2} MB/s", speed_mb_per_sec);
    log::info!("Total time: {:.2} seconds", end_time.as_secs_f64());
}
