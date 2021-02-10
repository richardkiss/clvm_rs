use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use pyo3::wrap_pyfunction;
use pyo3::PyObject;

//use super::arc_allocator::ArcAllocator;
use super::f_table::make_f_lookup;
use super::glue::{_py_run_program, _serialize_from_bytes, _serialize_to_bytes};
use super::native_op_lookup::GenericNativeOpLookup;
use super::py_allocator::PyNode;
use super::run_program::{__pyo3_get_function_serialize_and_run_program, STRICT_MODE};

type AllocatorT<'p> = Python<'p>;
type NodeClass = PyNode;

#[pyclass]
#[derive(Clone)]
pub struct NativeOpLookup {
    nol: usize, // Box<GenericNativeOpLookup<AllocatorT>>,
}

#[pymethods]
impl NativeOpLookup {
    #[new]
    fn new(native_opcode_list: &[u8], unknown_op_callback: PyObject) -> Self {
        let native_lookup = make_f_lookup::<AllocatorT>();
        let mut f_lookup = [None; 256];
        for i in native_opcode_list.iter() {
            let idx = *i as usize;
            f_lookup[idx] = native_lookup[idx];
        }
        let obj = Box::new(GenericNativeOpLookup::new(unknown_op_callback, f_lookup));

        NativeOpLookup {
            nol: Box::into_raw(obj) as usize,
        }
    }
}

impl Drop for NativeOpLookup {
    fn drop(&mut self) {
        let _b = unsafe { Box::from_raw(self.nol as *mut GenericNativeOpLookup<AllocatorT>) };
    }
}

impl NativeOpLookup {
    fn gnol<'a>(&self) -> &'a GenericNativeOpLookup<AllocatorT> {
        unsafe { &*(&self.nol as *const usize as *const GenericNativeOpLookup<AllocatorT>) }
    }
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn py_run_program(
    py: Python,
    program: &NodeClass,
    args: &NodeClass,
    quote_kw: u8,
    apply_kw: u8,
    max_cost: u32,
    op_lookup: NativeOpLookup,
    pre_eval: PyObject,
) -> PyResult<(u32, NodeClass)> {
    _py_run_program1(
        py,
        program,
        args,
        quote_kw,
        apply_kw,
        max_cost,
        op_lookup.gnol().clone(),
        pre_eval,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn _py_run_program1(
    py: Python,
    program: &PyNode,
    args: &PyNode,
    quote_kw: u8,
    apply_kw: u8,
    max_cost: u32,
    op_lookup: GenericNativeOpLookup<Python>,
    pre_eval: PyObject,
) -> PyResult<(u32, PyNode)> {
    let op_lookup: GenericNativeOpLookup<Python> = unsafe { std::mem::transmute(op_lookup) };
    let allocator: &Python = unsafe { std::mem::transmute(&py) };
    _py_run_program(
        py, allocator, program, args, quote_kw, apply_kw, max_cost, op_lookup, pre_eval,
    )
}

#[pyfunction]
fn raise_eval_error(py: Python, msg: &PyString, sexp: PyObject) -> PyResult<PyObject> {
    let ctx: &PyDict = PyDict::new(py);
    ctx.set_item("msg", msg)?;
    ctx.set_item("sexp", sexp)?;
    let r = py.run(
        "from clvm.EvalError import EvalError; raise EvalError(msg, sexp)",
        None,
        Some(ctx),
    );
    match r {
        Err(x) => Err(x),
        Ok(_) => Ok(ctx.into()),
    }
}

#[pyfunction]
fn serialize_from_bytes(py: Python, blob: &[u8]) -> NodeClass {
    _serialize_from_bytes(&py, blob)
}

#[pyfunction]
fn serialize_to_bytes(py: Python, sexp: &PyAny) -> PyResult<PyObject> {
    _serialize_to_bytes::<AllocatorT, NodeClass>(&py, py, sexp)
}

/// This module is a python module implemented in Rust.
#[pymodule]
fn clvm_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_run_program, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_and_run_program, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_from_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_to_bytes, m)?)?;

    m.add("STRICT_MODE", STRICT_MODE)?;

    m.add_class::<PyNode>()?;
    m.add_class::<NativeOpLookup>()?;

    m.add_function(wrap_pyfunction!(raise_eval_error, m)?)?;

    Ok(())
}
