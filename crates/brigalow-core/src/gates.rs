//! Public gate outcomes; no network endpoints or shared secrets enter domain records.
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result {
    pub gate: String,
    pub passed: bool,
    pub reason: String,
}
