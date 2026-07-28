use std::path::Path;

#[cfg(unix)]
mod unix {
    use super::Path;
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::ptr::NonNull;

    const PROT_READ: i32 = 0x1;
    const MAP_PRIVATE: i32 = 0x2;

    extern "C" {
        fn mmap(
            address: *mut c_void,
            length: usize,
            protection: i32,
            flags: i32,
            descriptor: i32,
            offset: i64,
        ) -> *mut c_void;
        fn munmap(address: *mut c_void, length: usize) -> i32;
    }

    pub struct MappedFile {
        pointer: NonNull<u8>,
        length: usize,
    }

    impl MappedFile {
        pub fn open(path: &Path) -> Result<Self, String> {
            let file = File::open(path).map_err(|error| format!("open package: {error}"))?;
            let length = file
                .metadata()
                .map_err(|error| format!("stat package: {error}"))?
                .len() as usize;
            if length == 0 {
                return Err("package is empty".to_string());
            }
            let raw = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    length,
                    PROT_READ,
                    MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                )
            };
            if raw as isize == -1 {
                return Err("memory-map package failed".to_string());
            }
            let pointer = NonNull::new(raw.cast::<u8>())
                .ok_or_else(|| "memory-map returned null".to_string())?;
            Ok(Self { pointer, length })
        }

        pub fn as_slice(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.length) }
        }
    }

    impl Drop for MappedFile {
        fn drop(&mut self) {
            unsafe {
                let _ = munmap(self.pointer.as_ptr().cast::<c_void>(), self.length);
            }
        }
    }

    unsafe impl Send for MappedFile {}
    unsafe impl Sync for MappedFile {}
}

#[cfg(not(unix))]
mod portable {
    use super::Path;
    use std::fs::File;
    use std::io::Read;

    pub struct MappedFile {
        data: Vec<u8>,
    }

    impl MappedFile {
        pub fn open(path: &Path) -> Result<Self, String> {
            let mut file = File::open(path).map_err(|error| format!("open package: {error}"))?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)
                .map_err(|error| format!("read package: {error}"))?;
            if data.is_empty() {
                return Err("package is empty".to_string());
            }
            Ok(Self { data })
        }

        pub fn as_slice(&self) -> &[u8] {
            &self.data
        }
    }
}

#[cfg(unix)]
pub use unix::MappedFile;
#[cfg(not(unix))]
pub use portable::MappedFile;
