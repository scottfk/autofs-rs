//! autofs' `modules/`, built in. Each file ports the module of the same name.

pub mod amd_parse;
pub mod lookup_dir;
pub mod lookup_file;
pub mod lookup_hosts;
pub mod lookup_multi;
pub mod lookup_program;
pub mod lookup_userhome;
pub mod lookup_yp;
pub mod mount_bind;
pub mod mount_generic;
pub mod mount_nfs;
pub mod parse_amd;
pub mod parse_sun;
