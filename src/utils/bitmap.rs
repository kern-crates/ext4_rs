/// Check if a bit is set in the bitmap
/// Parameter bmap: Bitmap array
/// Parameter bit: Bit index in the bitmap
pub fn ext4_bmap_is_bit_set(bmap: &[u8], bit: u32) -> bool {
    bmap[(bit >> 3) as usize] & (1 << (bit & 7)) != 0
}

/// Check if a bit is cleared in the bitmap
/// Parameter bmap: Bitmap array
/// Parameter bit: Bit index in the bitmap
pub fn ext4_bmap_is_bit_clr(bmap: &[u8], bit: u32) -> bool {
    !ext4_bmap_is_bit_set(bmap, bit)
}

/// Set a bit in the bitmap
/// Parameter bmap: Bitmap array
/// Parameter bit: Bit index in the bitmap
pub fn ext4_bmap_bit_set(bmap: &mut [u8], bit: u32) {
    bmap[(bit >> 3) as usize] |= 1 << (bit & 7);
}

/// Clear a bit in the bitmap
/// Parameter bmap: Bitmap array
/// Parameter bit: Bit index in the bitmap
pub fn ext4_bmap_bit_clr(bmap: &mut [u8], bit: u32) {
    bmap[(bit >> 3) as usize] &= !(1 << (bit & 7));
}

/// Find a free bit in the bitmap
/// Parameter bmap: Bitmap array
/// Parameter sbit: Start bit index
/// Parameter ebit: End bit index
/// Parameter bit_id: Reference to store the free bit index
pub fn ext4_bmap_bit_find_clr(bmap: &[u8], sbit: u32, ebit: u32, bit_id: &mut u32) -> bool {
    let mut i: u32;
    let mut bcnt = ebit - sbit;

    i = sbit;

    while i & 7 != 0 {
        if bcnt == 0 {
            return false;
        }

        if ext4_bmap_is_bit_clr(bmap, i) {
            *bit_id = sbit;
            return true;
        }

        i += 1;
        bcnt -= 1;
    }

    let mut sbit = i;
    let mut bmap = &bmap[(sbit >> 3) as usize..];
    while bcnt >= 8 {
        if bmap[0] != 0xFF {
            for i in 0..8 {
                if ext4_bmap_is_bit_clr(bmap, i) {
                    *bit_id = sbit + i;
                    return true;
                }
            }
        }

        bmap = &bmap[1..];
        bcnt -= 8;
        sbit += 8;
    }

    for i in 0..bcnt {
        if ext4_bmap_is_bit_clr(bmap, i) {
            *bit_id = sbit + i;
            return true;
        }
    }

    false
}

/// Clear a range of bits in the bitmap
/// Parameter bmap: Mutable reference to the bitmap array
/// Parameter start_bit: The start index of the bit range to clear
/// Parameter end_bit: The end index of the bit range to clear
pub fn ext4_bmap_bits_free(bmap: &mut [u8], start_bit: u32, end_bit: u32) {
    for bit in start_bit..=end_bit {
        ext4_bmap_bit_clr(bmap, bit);
    }
}