//! autofs' `daemon/`: `automount` itself.

pub mod automount;
pub mod direct;
pub mod flag;
pub mod indirect;
pub mod lookup;
pub mod master;
pub mod master_parse;
pub mod module;
pub mod mount;
pub mod spawn;
pub mod state;
