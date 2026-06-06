// Minimal MSF (DS, v7.00) container writer.
// Lays out a list of streams into 4096-byte blocks, builds the stream directory,
// the block map, and the free-page-map, and returns the full file bytes.

pub const BLOCK_SIZE: usize = 4096;
const MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

fn num_blocks(len: usize) -> usize {
    (len + BLOCK_SIZE - 1) / BLOCK_SIZE
}

/// True if block index is a Free-Page-Map block (recurs every BLOCK_SIZE blocks).
fn is_fpm(block: usize) -> bool {
    let m = block % BLOCK_SIZE;
    m == 1 || m == 2
}

/// Allocator that hands out usable (non-superblock, non-FPM) block indices.
struct Alloc {
    next: usize,
}
impl Alloc {
    fn new() -> Self {
        Alloc { next: 1 } // block 0 is the superblock
    }
    fn one(&mut self) -> usize {
        while is_fpm(self.next) {
            self.next += 1;
        }
        let b = self.next;
        self.next += 1;
        b
    }
    fn many(&mut self, n: usize) -> Vec<u32> {
        (0..n).map(|_| self.one() as u32).collect()
    }
}

fn le32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// Build the MSF file from the ordered list of stream byte-blobs.
/// Stream 0 is conventionally the "old directory" (usually empty).
pub fn build(streams: &[Vec<u8>]) -> Vec<u8> {
    let mut alloc = Alloc::new();

    // 1. Assign data blocks for every stream.
    let mut stream_blocks: Vec<Vec<u32>> = Vec::with_capacity(streams.len());
    for s in streams {
        let nb = num_blocks(s.len());
        stream_blocks.push(alloc.many(nb));
    }

    // 2. Build the stream directory.
    //    u32 NumStreams; u32 Sizes[N]; u32 Blocks[N][..]
    let mut dir = Vec::new();
    le32(&mut dir, streams.len() as u32);
    for s in streams {
        le32(&mut dir, s.len() as u32);
    }
    for blks in &stream_blocks {
        for &b in blks {
            le32(&mut dir, b);
        }
    }

    // 3. Assign blocks for the directory itself, then the block-map block(s).
    let dir_blocks = alloc.many(num_blocks(dir.len()));
    // block map = array of the directory block indices
    let mut blockmap = Vec::new();
    for &b in &dir_blocks {
        le32(&mut blockmap, b);
    }
    let blockmap_blocks = alloc.many(num_blocks(blockmap.len().max(1)));
    let block_map_addr = blockmap_blocks[0];

    let total_blocks = alloc.next;

    // 4. Compose the file.
    let mut file = vec![0u8; total_blocks * BLOCK_SIZE];

    // Superblock.
    {
        let sb = &mut file[..56];
        sb[..32].copy_from_slice(MAGIC);
        sb[32..36].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes());
        sb[36..40].copy_from_slice(&1u32.to_le_bytes()); // FreeBlockMapBlock = 1
        sb[40..44].copy_from_slice(&(total_blocks as u32).to_le_bytes());
        sb[44..48].copy_from_slice(&(dir.len() as u32).to_le_bytes());
        sb[48..52].copy_from_slice(&0u32.to_le_bytes()); // Unknown
        sb[52..56].copy_from_slice(&block_map_addr.to_le_bytes());
    }

    let write_blocks = |file: &mut Vec<u8>, blocks: &[u32], data: &[u8]| {
        for (i, &b) in blocks.iter().enumerate() {
            let src = &data[i * BLOCK_SIZE..((i + 1) * BLOCK_SIZE).min(data.len())];
            let dst = (b as usize) * BLOCK_SIZE;
            file[dst..dst + src.len()].copy_from_slice(src);
        }
    };

    for (s, blks) in streams.iter().zip(&stream_blocks) {
        write_blocks(&mut file, blks, s);
    }
    write_blocks(&mut file, &dir_blocks, &dir);
    write_blocks(&mut file, &blockmap_blocks, &blockmap);

    // 5. Free Page Map: bit=1 => free, bit=0 => used. Mark everything used that we
    //    allocated; leave the rest free. We only populate the active FPM (block 1
    //    and its recurrences); fill the inactive FPM (block 2 series) as all-free.
    let mut used = vec![false; total_blocks];
    used[0] = true; // superblock
    for b in 0..total_blocks {
        if is_fpm(b) {
            used[b] = true;
        }
    }
    for blks in stream_blocks.iter().chain([dir_blocks, blockmap_blocks].iter()) {
        for &b in blks {
            used[b as usize] = true;
        }
    }
    // Free Page Map: each FPM block holds a LINEAR bitmap of BLOCK_SIZE*8 = 32768
    // file blocks. FPM block #k (covering blocks [k*32768, (k+1)*32768)) lives at
    // file block (1 + k*BLOCK_SIZE) for the active series (FreeBlockMapBlock = 1).
    // The inactive series (block 2 + k*BLOCK_SIZE) is left all-free (0xFF).
    const FPM_COVER: usize = BLOCK_SIZE * 8; // blocks described by one FPM block
    let num_fpm = (total_blocks + FPM_COVER - 1) / FPM_COVER;
    // first, default every reserved FPM-position block to all-free
    let mut pos = 1usize;
    while pos < total_blocks {
        for byte in 0..BLOCK_SIZE {
            file[pos * BLOCK_SIZE + byte] = 0xFF;
        }
        // jump to the next reserved position (the 2-series sibling, then next interval)
        pos += if pos % BLOCK_SIZE == 1 { 1 } else { BLOCK_SIZE - 1 };
    }
    // write the active FPM blocks with the real used/free bitmap
    for k in 0..num_fpm {
        let fpm_index = 1 + k * BLOCK_SIZE;
        let base = fpm_index * BLOCK_SIZE;
        for byte in 0..BLOCK_SIZE {
            let mut v = 0u8;
            for bit in 0..8 {
                let blk = k * FPM_COVER + byte * 8 + bit;
                let is_free = if blk < total_blocks { !used[blk] } else { true };
                if is_free {
                    v |= 1 << bit;
                }
            }
            file[base + byte] = v;
        }
    }

    file
}
