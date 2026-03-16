//! # DriftDB Query
//!
//! DriftQL — the query language for DriftDB.
//! Provides lexer, parser, AST, and executor.

pub mod ast;
pub mod executor;
pub mod lexer;
pub mod parser;

pub use executor::{Executor, QueryResult};
pub use parser::parse;
