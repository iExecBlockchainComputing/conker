use serde::Serialize;
use std::fmt::{Display, Formatter};

use crate::logger_debug;
use tracing::{debug, error, /*event,*/ info /*, trace, warn*/};

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
      //
      logger_debug!("");

        write!(f, "{:?}", self)
    }
}
