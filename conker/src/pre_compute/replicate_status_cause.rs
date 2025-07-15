use serde::Serialize;
use std::fmt::{Display, Formatter};

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(clippy::enum_variant_names)]
pub enum ReplicateStatusCause {
    PreComputeOutputPathMissing, //exit 1 (known)
    PreComputeIsDatasetRequiredMissing,
    PreComputeDatasetUrlMissing,
    PreComputeDatasetKeyMissing,
    PreComputeDatasetChecksumMissing,
    PreComputeDatasetFilenameMissing,
    PreComputeInputFilesNumberMissing,
    PreComputeAtLeastOneInputFileUrlMissing,
    PreComputeOutputFolderNotFound,
    PreComputeDatasetDownloadFailed,
    PreComputeInvalidDatasetChecksum,
    PreComputeDatasetDecryptionFailed,
    PreComputeSavingPlainDatasetFailed,
    PreComputeInputFileDownloadFailed,
    PreComputeFailedUnknownIssue, //exit 1 (unknown)
}

impl Display for ReplicateStatusCause {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
