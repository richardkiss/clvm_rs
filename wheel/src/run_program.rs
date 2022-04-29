use std::collections::HashMap;
use std::rc::Rc;

use crate::lazy_node::LazyNode;
use clvmr::allocator::Allocator;
use clvmr::chia_dialect::ChiaDialect;
use clvmr::cost::Cost;
use clvmr::reduction::Response;
use clvmr::run_program::run_program;
use clvmr::runtime_dialect::RuntimeDialect;
use clvmr::serialize::{node_from_bytes, serialized_length_from_bytes};

use pyo3::prelude::*;

fn adapt_response(
    py: Python,
    allocator: Allocator,
    response: Response,
) -> PyResult<(PyObject, LazyNode)> {
    match response {
        Ok(reduction) => {
            let val = LazyNode::new(Rc::new(allocator), reduction.1);
            let rv: PyObject = reduction.0.into_py(py);
            Ok((rv, val))
        }
        Err(eval_err) => {
            let rv: PyObject = eval_err.1.into_py(py);
            let val = LazyNode::new(Rc::new(allocator), eval_err.0);
            Ok((rv, val))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_serialized_program(
    py: Python,
    allocator: &mut Allocator,
    quote_kw: &[u8],
    apply_kw: &[u8],
    opcode_lookup_by_name: HashMap<String, Vec<u8>>,
    program: &[u8],
    args: &[u8],
    max_cost: Cost,
    flags: u32,
) -> PyResult<Response> {
    let program = node_from_bytes(allocator, program)?;
    let args = node_from_bytes(allocator, args)?;
    let dialect = RuntimeDialect::new(
        opcode_lookup_by_name,
        quote_kw.to_vec(),
        apply_kw.to_vec(),
        flags,
    );

    Ok(py.allow_threads(|| run_program(allocator, &dialect, program, args, max_cost, None)))
}

#[pyfunction]
pub fn serialized_length(program: &[u8]) -> PyResult<u64> {
    Ok(serialized_length_from_bytes(program)?)
}

#[allow(clippy::too_many_arguments)]
#[pyfunction]
pub fn deserialize_and_run_program2(
    py: Python,
    program: &[u8],
    args: &[u8],
    quote_kw: u8,
    apply_kw: u8,
    opcode_lookup_by_name: HashMap<String, Vec<u8>>,
    max_cost: Cost,
    flags: u32,
) -> PyResult<(PyObject, LazyNode)> {
    let mut allocator = Allocator::new();
    let r = run_serialized_program(
        py,
        &mut allocator,
        &[quote_kw],
        &[apply_kw],
        opcode_lookup_by_name,
        program,
        args,
        max_cost,
        flags,
    )?;
    adapt_response(py, allocator, r)
}

#[pyfunction]
pub fn run_chia_program(
    py: Python,
    program: &[u8],
    args: &[u8],
    max_cost: Cost,
    flags: u32,
) -> PyResult<(PyObject, LazyNode)> {
    let mut allocator = Allocator::new();

    let r: Response = (|| -> PyResult<Response> {
        let program = node_from_bytes(&mut allocator, program)?;
        let args = node_from_bytes(&mut allocator, args)?;
        let dialect = ChiaDialect::new(flags);

        Ok(py
            .allow_threads(|| run_program(&mut allocator, &dialect, program, args, max_cost, None)))
    })()?;
    adapt_response(py, allocator, r)
}
