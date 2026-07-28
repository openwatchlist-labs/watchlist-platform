mod format;
mod input;
mod mmap;
mod sha256;
mod worker;

use std::path::Path;

pub use format::{
    compile, normalize_identifier, normalize_name, normalize_type, CandidateMatch, PackageInfo,
    PackageView, COMPILER_VERSION, FORMAT_VERSION, MAGIC, PACKAGE_SCHEMA_VERSION,
};
pub use mmap::MappedFile;
pub use worker::{handle_request_line, run_worker, WORKER_PROTOCOL_VERSION};

pub struct MappedPackage {
    mapped: MappedFile,
}

impl MappedPackage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let mapped = MappedFile::open(path.as_ref())?;
        PackageView::open(mapped.as_slice())?;
        Ok(Self { mapped })
    }

    pub fn view(&self) -> Result<PackageView<'_>, String> {
        PackageView::open(self.mapped.as_slice())
    }
}
