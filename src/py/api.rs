use super::arc_allocator::{ArcAllocator, ArcSExp};
use super::native_op_lookup::INativeOpLookup;
use super::py_node::PyNode;
use super::py_support::PythonSupport;
use crate::allocator::Allocator;
use crate::node::Node;
use crate::py::run_program::__pyo3_get_function_serialize_and_run_program;
use crate::reduction::{EvalErr, Reduction};
use crate::run_program::{run_program, OperatorHandler, PostEval, PreEval};
use crate::serialize::{node_from_bytes, node_to_bytes};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyString};
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
    let allocator = ArcAllocator::new();

    let py_pre_eval_t: Option<PreEval<ArcAllocator>> = if pre_eval.is_none(py) {
        None
    } else {
        Some(Box::new(move |program: &ArcSExp, args: &ArcSExp| {
            Python::with_gil(|py| {
                let program_clone: PyNode = program.into();
                let args: PyNode = args.into();
                let r: PyResult<PyObject> = pre_eval.call1(py, (program_clone, args));
                match r {
                    Ok(py_post_eval) => {
                        let f = post_eval_for_pyobject::<ArcAllocator>(py_post_eval);
                        Ok(f)
                    }
                    Err(ref err) => allocator.err(program, &err.to_string()),
                }
            })
        }))
    };

    // BRAIN DAMAGE: we create a second `ArcAllocator` here
    // This only works because this allocator type has the property that
    // you can create a pair from nodes from different allocators.

    let allocator: ArcAllocator = ArcAllocator::new();
    let f: OperatorHandler<ArcAllocator> =
        Box::new(move |allocator, op, args| op_lookup.operator_handler(allocator, op, args));

    let r: Result<Reduction<ArcSExp>, EvalErr<ArcSExp>> = run_program(
        &allocator,
        &program.into(),
        &args.into(),
        quote_kw,
        apply_kw,
        max_cost,
        &f,
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

fn _py_run_program<A: 'static, P>(
    py: Python,
    program: &P,
    args: &P,
    quote_kw: u8,
    apply_kw: u8,
    max_cost: u32,
    op_lookup: INativeOpLookup<A>,
    pre_eval: PyObject,
) -> PyResult<(u32, P)>
where
    A: Allocator<Ptr = P> + Default,
    P: PythonSupport + Clone + ToPyObject,
{
    let allocator = A::default();

    let py_pre_eval_t: Option<PreEval<A>> = None /* if pre_eval.is_none(py) {
        None
    } else {
        Some(Box::new(move |program: &P, args: &P| {
            Python::with_gil(|py| {
                let program_clone: PyNode = program.into();
                let args: PyNode = args.into();
                let r: PyResult<PyObject> = pre_eval.call1(py, (program_clone, args));
                match r {
                    Ok(py_post_eval) => {
                        let f = post_eval_for_pyobject::<A>(py_post_eval);
                        Ok(f)
                    }
                    Err(ref err) => allocator.err(program, &err.to_string()),
                }
            })
        }))
    }*/ ;

    // BRAIN DAMAGE: we create a second `A` here
    // This only works because this allocator type has the property that
    // you can create a pair from nodes from different allocators.

    let allocator: A = A::default();
    let f: OperatorHandler<A> =
        Box::new(move |allocator, op, args| op_lookup.operator_handler(allocator, op, args));

    let r: Result<Reduction<P>, EvalErr<P>> = run_program(
        &allocator,
        &program,
        &args,
        quote_kw,
        apply_kw,
        max_cost,
        &f,
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
    let msg_any: PyObject = msg.into_py(py);

    let s0: &PyString = PyString::new(py, "msg");
    let s1: &PyString = PyString::new(py, "sexp");
    let ctx: &PyDict = PyDict::new(py);
    ctx.set_item(s0, msg_any)?;
    ctx.set_item(s1, sexp)?;

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

#[pyclass]
#[derive(Clone)]
pub struct NativeOpLookup {
    nol: INativeOpLookup<ArcAllocator>,
}

#[pymethods]
impl NativeOpLookup {
    #[new]
    fn new(unknown_op_callback: PyObject) -> Self {
        NativeOpLookup {
            nol: INativeOpLookup::new(unknown_op_callback),
        }
    }

    fn add_native(&mut self, opcode: u8, name: &str) -> PyResult<bool> {
        self.nol.add_native(opcode, name)
    }
}

impl NativeOpLookup {
    pub fn operator_handler(
        &self,
        allocator: &ArcAllocator,
        op: &[u8],
        argument_list: &ArcSExp,
    ) -> Result<Reduction<ArcSExp>, EvalErr<ArcSExp>> {
        self.nol.operator_handler(allocator, op, argument_list)
    }
}

#[pyfunction]
fn serialize_from_bytes(blob: &[u8]) -> PyNode {
    let allocator: ArcAllocator = ArcAllocator::new();
    node_from_bytes(&allocator, blob).unwrap().into()
}

#[pyfunction]
fn serialize_to_bytes(py: Python, sexp: &PyAny) -> PyResult<PyObject> {
    _serialize_to_bytes(&ArcAllocator::new(), py, sexp)
}

fn _serialize_to_bytes<A: Allocator<Ptr = P>, P>(
    allocator: &A,
    py: Python,
    sexp: &PyAny,
) -> PyResult<PyObject>
where
    P: PythonSupport,
{
    let node_t: Node<A> = Node::new(allocator, P::py_object_to_ptr(sexp)?);
    let blob = node_to_bytes(&node_t).unwrap();
    let pybytes = PyBytes::new(py, &blob);
    Ok(pybytes.to_object(py))
}

/// This module is a python module implemented in Rust.
#[pymodule]
fn clvm_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_run_program, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_and_run_program, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_from_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_to_bytes, m)?)?;

    m.add_class::<PyNode>()?;
    m.add_class::<NativeOpLookup>()?;

    m.add_function(wrap_pyfunction!(raise_eval_error, m)?)?;

    Ok(())
}
