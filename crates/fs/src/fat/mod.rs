use crate::tree::FsTree;
use std::sync::Arc;
use strata_kernel::Result;
use strata_source::BlockSource;

pub(crate) fn open(_source: Arc<dyn BlockSource>) -> Result<FsTree> {
    Err(strata_kernel::Error::format("todo"))
}
