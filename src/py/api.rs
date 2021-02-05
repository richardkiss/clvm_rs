use super::arc_allocator::{ArcAllocator, ArcSExp};
use super::native_op_lookup::NativeOpLookup;
use super::py_node::PyNode;
use crate::allocator::Allocator;
use crate::node::Node;
use crate::py::run_program::__pyo3_get_function_serialize_and_run_program;
use crate::reduction::{EvalErr, Reduction};
use crate::run_program::{run_program, PostEval, PreEval};
use crate::serialize::{node_from_bytes, node_to_bytes};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use pyo3::wrap_pyfunction;
use pyo3::PyObject;

fn note_result<T>(obj: &PyObject, result: Option<&T>)
where
    T: ToPyObject,
{
    Python::with_gil(|py| {
        if let Some(node) = result {
            let node: PyObject = node.to_object(py);
            let _r: PyResult<PyObject> = obj.call1(py, (node,));
        }
    });
}

fn post_eval_for_pyobject<A: Allocator>(obj: PyObject) -> Option<Box<PostEval<A>>>
where
    A::Ptr: ToPyObject,
{
    let py_post_eval: Option<Box<PostEval<A>>> = if Python::with_gil(|py| obj.is_none(py)) {
        None
    } else {
        Some(Box::new(move |result: Option<&A::Ptr>| {
            note_result(&obj, result)
        }))
    };
    py_post_eval
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn py_run_program(
    py: Python,
    program: &PyNode,
    args: &PyNode,
    quote_kw: u8,
    apply_kw: u8,
    max_cost: u32,
    op_lookup: NativeOpLookup,
    pre_eval: PyObject,
) -> PyResult<(u32, PyNode)> {
    let py_pre_eval_t: Option<PreEval<ArcAllocator>> = if pre_eval.is_none(py) {
        None
    } else {
        Some(Box::new(move |allocator, program, args| {
            Python::with_gil(|py| {
                let program_clone: PyNode = program.into();
                let args: PyNode = args.into();
                let r: PyResult<PyObject> = pre_eval.call1(py, (program_clone, args));
                match r {
                    Ok(py_post_eval) => Ok(post_eval_for_pyobject::<ArcAllocator>(py_post_eval)),
                    Err(ref err) => (allocator
                        as &dyn Allocator<Ptr = <ArcAllocator as Allocator>::Ptr>)
                        .err(program, &err.to_string()),
                }
            })
        }))
    };

    let r: Result<Reduction<ArcSExp>, EvalErr<ArcSExp>> = run_program(
        &ArcAllocator::new(),
        &program.into(),
        &args.into(),
        quote_kw,
        apply_kw,
        max_cost,
        &op_lookup.make_operator_handler(),
        py_pre_eval_t,
    );
    match r {
        Ok(reduction) => Ok((reduction.0, reduction.1.into())),
        Err(eval_err) => {
            let node: PyObject = eval_err.0.to_object(py);
            let s: String = eval_err.1;
            let s1: &str = &s;
            let msg: &PyString = PyString::new(py, s1);
            match raise_eval_error(py, &msg, node) {
                Err(x) => Err(x),
                _ => panic!(),
            }
        }
    }
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
fn serialize_from_bytes(blob: &[u8]) -> ArcSExp {
    let allocator: ArcAllocator = ArcAllocator::new();
    node_from_bytes(&allocator, blob).unwrap()
}

#[pyfunction]
fn serialize_to_bytes(sexp: &PyNode) -> Vec<u8> {
    let allocator: ArcAllocator = ArcAllocator::new();
    let node_t: Node<ArcAllocator> = Node::new(&allocator, sexp.into());
    node_to_bytes(&node_t).unwrap()
}

use crate::persist::Persist;

/// This module is a python module implemented in Rust.
#[pymodule]
fn clvm_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_run_program, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_and_run_program, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_from_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_to_bytes, m)?)?;

    m.add_class::<PyNode>()?;
    m.add_class::<NativeOpLookup>()?;
    m.add_class::<Persist>()?;

    m.add_function(wrap_pyfunction!(raise_eval_error, m)?)?;

    Ok(())
}
