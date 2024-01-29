extern crate alloc;
extern crate log;

use alloc::string;
use alloc::vec;
use bitflags::Flags;
use core::marker::PhantomData;
use core::mem::size_of;
use core::str;
use core::*;

use super::ext4_defs::*;
use crate::consts::*;
use crate::prelude::*;
use crate::utils::*;

pub(crate) const BASE_OFFSET: usize = 1024;
pub(crate) const BLOCK_SIZE: usize = 4096;

// 定义ext4_ext_binsearch函数，接受一个指向ext4_extent_path的可变引用和一个逻辑块号，返回一个布尔值，表示是否找到了对应的extent
pub fn ext4_ext_binsearch(path: &mut Ext4ExtentPath, block: u32) -> bool {
    // 获取extent header的引用
    let eh = unsafe { &*path.header };

    if eh.entries_count == 0 {
        /*
         * this leaf is empty:
         * we get such a leaf in split/add case
         */
        false;
    }

    // 定义左右两个指针，分别指向第一个和最后一个extent
    let mut l = unsafe { ext4_first_extent(eh).add(1) };
    let mut r = unsafe { ext4_last_extent(eh) };

    // 如果extent header中没有有效的entry，直接返回false
    if eh.entries_count == 0 {
        return false;
    }
    // 使用while循环进行二分查找
    while l <= r {
        // 计算中间指针
        let m = unsafe { l.add((r as usize - l as usize) / 2) };
        // 获取中间指针所指向的extent的引用
        let ext = unsafe { &*m };
        // 比较逻辑块号和extent的第一个块号
        if block < ext.first_block {
            // 如果逻辑块号小于extent的第一个块号，说明目标在左半边，将右指针移动到中间指针的左边
            r = unsafe { m.sub(1) };
        } else {
            // 如果逻辑块号大于或等于extent的第一个块号，说明目标在右半边，将左指针移动到中间指针的右边
            l = unsafe { m.add(1) };
        }
    }
    // 循环结束后，将path的extent字段设置为左指针的前一个位置
    path.extent = unsafe { l.sub(1) };
    // 返回true，表示找到了对应的extent
    true
}

pub trait BlockDevice: Send + Sync + Any + Debug {
    fn read_offset(&self, offset: usize) -> Vec<u8>;
    fn write_offset(&self, offset: usize, data: &[u8]);
}

impl dyn BlockDevice {
    pub fn downcast_ref<T: BlockDevice>(&self) -> Option<&T> {
        (self as &dyn Any).downcast_ref::<T>()
    }
}

#[derive(Debug)]
pub struct Ext4 {
    pub block_device: Arc<dyn BlockDevice>,
    pub super_block: Ext4Superblock,
    pub block_groups: Vec<Ext4BlockGroup>,
    pub inodes_per_group: u32,
    pub blocks_per_group: u32,
    pub inode_size: usize,
    pub self_ref: Weak<Self>,
    pub mount_point: Ext4MountPoint,
}

impl Ext4 {
    /// Opens and loads an Ext4 from the `block_device`.
    pub fn open(block_device: Arc<dyn BlockDevice>) -> Arc<Self> {
        // Load the superblock
        // TODO: if the main superblock is corrupted, should we load the backup?
        let raw_data = block_device.read_offset(BASE_OFFSET);
        let super_block = Ext4Superblock::try_from(raw_data).unwrap();

        println!("super_block: {:x?}", super_block);
        let inodes_per_group = super_block.inodes_per_group();
        let blocks_per_group = super_block.blocks_per_group();
        let inode_size = super_block.inode_size();

        // Load the block groups information
        let load_block_groups =
            |fs: Weak<Ext4>, block_device: Arc<dyn BlockDevice>| -> Result<Vec<Ext4BlockGroup>> {
                let block_groups_count = super_block.block_groups_count() as usize;
                let mut block_groups = Vec::with_capacity(block_groups_count);
                for idx in 0..block_groups_count {
                    let block_group =
                        Ext4BlockGroup::load(block_device.clone(), &super_block, idx).unwrap();
                    block_groups.push(block_group);
                }
                Ok(block_groups)
            };

        let mount_point = Ext4MountPoint::new("/");

        let ext4 = Arc::new_cyclic(|weak_ref| Self {
            super_block: super_block,
            inodes_per_group: inodes_per_group,
            blocks_per_group: blocks_per_group,
            inode_size: inode_size as usize,
            block_groups: load_block_groups(weak_ref.clone(), block_device.clone()).unwrap(),
            block_device,
            self_ref: weak_ref.clone(),
            mount_point: mount_point,
        });

        ext4
    }

    // 使用libc库定义的常量
    fn ext4_parse_flags(&self, flags: &str) -> Result<u32> {
        let flag = flags.parse::<Ext4OpenFlags>().unwrap(); // 从字符串转换为标志
        let file_flags = match flag {
            Ext4OpenFlags::ReadOnly => O_RDONLY,
            Ext4OpenFlags::WriteOnly => O_WRONLY,
            Ext4OpenFlags::WriteCreateTrunc => O_WRONLY | O_CREAT | O_TRUNC,
            Ext4OpenFlags::WriteCreateAppend => O_WRONLY | O_CREAT | O_APPEND,
            Ext4OpenFlags::ReadWrite => O_RDWR,
            Ext4OpenFlags::ReadWriteCreateTrunc => O_RDWR | O_CREAT | O_TRUNC,
            Ext4OpenFlags::ReadWriteCreateAppend => O_RDWR | O_CREAT | O_APPEND,
        };
        Ok(file_flags as u32) // 转换为数值
    }

    // start transaction
    pub fn ext4_trans_start(&self) {}

    // stop transaction
    pub fn ext4_trans_abort(&self) {}

    pub fn ext4_open(&self, file: &mut Ext4File, path: &str, flags: &str, file_expect: bool) {
        let mut iflags = 0;
        let mut filetype = DirEntryType::EXT4_DE_UNKNOWN;

        // get mount point
        let mut ptr = Box::new(self.mount_point.clone());
        file.mp = Box::as_mut(&mut ptr) as *mut Ext4MountPoint;

        // get open flags
        iflags = self.ext4_parse_flags(flags).unwrap();

        // file for dir
        if file_expect {
            filetype = DirEntryType::EXT4_DE_REG_FILE;
        } else {
            filetype = DirEntryType::EXT4_DE_DIR;
        }

        if iflags & O_CREAT != 0 {
            self.ext4_trans_start();
        }
        self.ext4_generic_open(file, path, iflags, filetype.bits(), None);
    }

    pub fn ext4_generic_open(
        &self,
        file: &mut Ext4File,
        path: &str,
        iflags: u32,
        ftype: u8,
        parent_inode: Option<&mut Ext4InodeRef>,
    ) {
        let mut is_goal = false;

        let mp: &Ext4MountPoint = &self.mount_point;

        let mp_name = mp.mount_name.as_bytes();

        let mut data: Vec<u8> = Vec::with_capacity(BLOCK_SIZE);
        let ext4_blk = Ext4Block {
            logical_block_id: 0,
            disk_block_id: 0,
            block_data: &mut data,
            dirty: true,
        };
        let mut de = Ext4DirEntry::default();
        let mut dir_search_result = Ext4DirSearchResult::new(ext4_blk, de);
        let path_skip_mount = ext4_path_skip(path, core::str::from_utf8(mp_name).unwrap());

        file.flags = iflags;

        // load root inode
        let mut root_inode_ref = Ext4InodeRef::get_inode_ref(self.self_ref.clone(), 2);

        if !parent_inode.is_none() {
            parent_inode.unwrap().inode_num = root_inode_ref.inode_num;
        }

        let mut len = ext4_path_check(path_skip_mount, &mut is_goal);

        let mut serach_path = path_skip_mount;

        loop {
            len = ext4_path_check(&serach_path, &mut is_goal);

            let r = ext4_dir_find_entry(
                &mut root_inode_ref,
                serach_path,
                len as u32,
                &mut dir_search_result,
            );

            if r != EOK {
                ext4_dir_destroy_result();

                let mut child_inode_ref = Ext4InodeRef::new(self.self_ref.clone());

                let r = ext4_fs_alloc_inode(&mut child_inode_ref);

                if r != EOK {
                    break;
                }

                ext4_fs_inode_blocks_init(&mut child_inode_ref);

                let r = ext4_link();

                if r != EOK {
                    /*Fail. Free new inode.*/
                    break;
                }

                ext4_fs_put_inode_ref(&mut child_inode_ref);
            }
        }
    }
}

pub fn ext4_fs_put_inode_ref(inode_ref: &mut Ext4InodeRef) {
    inode_ref.inner.write_back_inode();
}

pub fn ext4_link() -> usize {
    0
}

pub fn ext4_fs_inode_blocks_init(inode_ref: &mut Ext4InodeRef) {}

pub fn ext4_fs_alloc_inode(child_inode_ref: &mut Ext4InodeRef) -> usize {
    0
}
pub fn ext4_dir_destroy_result() {}

pub fn ext4_dir_find_entry(
    parent: &mut Ext4InodeRef,
    name: &str,
    name_len: u32,
    result: &mut Ext4DirSearchResult,
) -> usize {
    println!("ext4_dir_find_entry {:?}", name);
    let mut iblock = 0;
    let mut fblock: ext4_fsblk_t = 0;

    let inode_size: u32 = parent.inner.inode.size;
    let total_blocks: u32 = inode_size / BLOCK_SIZE as u32;

    while iblock < total_blocks {
        ext4_fs_get_inode_dblk_idx(parent, iblock, &mut fblock, false);

        // load_block
        let mut data = parent.fs().block_device.read_offset(fblock as usize);
        let mut ext4_block = Ext4Block {
            logical_block_id: iblock,
            disk_block_id: fblock,
            block_data: &mut data,
            dirty: false,
        };

        let r = ext4_dir_find_in_block(&mut ext4_block, name_len, name, result);

        if r {
            return EOK;
        }

        iblock += 1
    }

    0
}

pub fn ext4_extent_get_blocks(
    inode_ref: &mut Ext4InodeRef,
    iblock: ext4_lblk_t,
    max_blocks: u32,
    result: &mut ext4_fsblk_t,
    create: bool,
    blocks_count: &mut u32,
) {
    let inode = &mut inode_ref.inner.inode;

    let mut vec_extent_path: Vec<Ext4ExtentPath> = Vec::with_capacity(3);

    let mut extent_path = Ext4ExtentPath::default();

    ext4_find_extent(inode, iblock, &mut extent_path, &mut vec_extent_path);

    let depth = unsafe { *ext4_inode_hdr(inode) }.depth;

    let ex: Ext4Extent = unsafe { *vec_extent_path[depth as usize].extent };

    let ee_block = ex.first_block;
    let ee_start = ex.start_lo | (((ex.start_hi as u32) << 31) << 1);
    let ee_len: u16 = ex.block_count;

    if iblock >= ee_block && iblock <= (ee_block + ee_len as u32) {
        let newblock = iblock - ee_block + ee_start;
        *result = newblock as u64;

        return;
    }
}

pub fn ext4_find_extent(
    inode: &Ext4Inode,
    iblock: ext4_lblk_t,
    orig_path: &mut Ext4ExtentPath,
    v: &mut Vec<Ext4ExtentPath>,
) {
    let eh = &inode.block as *const [u32; 15] as *const Ext4ExtentHeader;

    let extent_header = Ext4ExtentHeader::try_from(&inode.block[..2]).unwrap();

    let depth = extent_header.depth;

    let mut extent_path = Ext4ExtentPath::default();
    extent_path.depth = depth;
    extent_path.header = eh;

    // depth = 0
    ext4_ext_binsearch(&mut extent_path, iblock);
    let extent = unsafe { *extent_path.extent };
    let pblock = extent.start_lo | (((extent.start_hi as u32) << 31) << 1);
    extent_path.p_block = pblock;

    v.push(extent_path);
}

pub fn ext4_fs_get_inode_dblk_idx(
    inode_ref: &mut Ext4InodeRef,
    iblock: ext4_lblk_t,
    fblock: &mut ext4_fsblk_t,
    extent_create: bool,
) {
    let mut current_block: ext4_fsblk_t;
    let mut current_fsblk: ext4_fsblk_t = 0;

    let mut blocks_count = 0;
    ext4_extent_get_blocks(
        inode_ref,
        iblock,
        1,
        &mut current_fsblk,
        false,
        &mut blocks_count,
    );

    current_block = current_fsblk;
    *fblock = current_block;
}

pub fn ext4_dir_find_in_block(
    block: &Ext4Block,
    name_len: u32,
    name: &str,
    result: &mut Ext4DirSearchResult,
) -> bool {
    let mut offset = 0;

    while offset < block.block_data.len() {
        let de = Ext4DirEntry::try_from(&block.block_data[offset..]).unwrap();

        offset = offset + de.entry_len as usize;
        if de.inode == 0 {
            continue;
        }
        let s = get_name(de.name, de.name_len as usize);

        if let Ok(s) = s {
            if name_len == de.name_len as u32 {
                if name.to_string() == s {
                    println!(
                        "found s {:?}  name_len {:x?} de.name_len {:x?}",
                        s, name_len, de.name_len
                    );
                    result.dentry.entry_len = de.entry_len;
                    result.dentry.name = de.name;
                    result.dentry.name_len = de.name_len;
                    unsafe {
                        result.dentry.inner.name_length_high = de.inner.name_length_high;
                    }
                    result.dentry.inode = de.inode;

                    return true;
                }
            }
        }
    }

    false
}
