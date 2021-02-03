use crate::allocator::Allocator;
use crate::node::Node;
use crate::reduction::{EvalErr, Reduction};

use super::arc_allocator::{ArcAllocator, ArcSExp};
use super::f_table::{opcode_by_name, FLookup};
use super::py_node::PyNode;

use pyo3::exceptions::PyBaseException;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyTuple};

#[pyclass]
#[derive(Clone)]
pub struct NativeOpLookup {
    nol: INativeOpLookup<ArcAllocator>,
}

#[derive(Clone)]
struct INativeOpLookup<A: Allocator> {
    py_callback: PyObject,
    f_lookup: FLookup<A>,
}

#[pymethods]
impl NativeOpLookup {
    #[new]
    fn new(unknown_op_callback: &PyAny) -> Self {
        let f_lookup: FLookup<ArcAllocator> = [None; 256];
        NativeOpLookup {
            nol: INativeOpLookup {
                py_callback: unknown_op_callback.into(),
                f_lookup,
            },
        }
    }

    fn add_native(&mut self, opcode: u8, name: &str) -> PyResult<bool> {
        let f = opcode_by_name(name);
        self.nol.f_lookup[opcode as usize] = f;
        Ok(f.is_some())
    }
}

impl<A: Allocator> ToPyObject for Node<'_, A>
where
    A::Ptr: ToPyObject,
{
    fn to_object(&self, py: Python<'_>) -> PyObject {
        self.ptr().to_object(py)
    }
}

impl<'p> FromPyObject<'p> for ArcSExp {
    fn extract(obj: &PyAny) -> PyResult<Self> {
        let sexp_ptr: PyRef<PyNode> = obj.extract()?;
        let node: ArcSExp = (&sexp_ptr as &PyNode).into();
        Ok(node)
    }
}

fn eval_err_for_pyerr<'p, A: Allocator, T>(
    _node: &Node<'_, A>,
    py: Python<'p>,
    pyerr: &'p PyErr,
) -> PyResult<EvalErr<T>>
where
    T: FromPyObject<'p>,
{
    let be: &PyBaseException = pyerr.pvalue(py);
    let sexp: &PyAny = be.getattr("_sexp")?;
    let node: T = sexp.extract()?;

    let args: &PyAny = be.getattr("args")?;
    let args: &PyTuple = args.extract()?;
    let arg0: &PyString = args.get_item(0).extract()?;
    let s: &str = arg0.to_str()?;
    let s: String = s.to_string();
    Ok(EvalErr(node, s))
}

fn unwrap_or_eval_err<T, A: Allocator>(
    obj: PyResult<T>,
    node: &Node<'_, A>,
    msg: &str,
) -> Result<T, EvalErr<<A as Allocator>::Ptr>> {
    match obj {
        Err(_py_err) => Err(EvalErr(node.ptr(), msg.to_string())),
        Ok(o) => Ok(o),
    }
}

impl NativeOpLookup {
    pub fn operator_handler(
        &self,
        allocator: &ArcAllocator,
        op: &[u8],
        argument_list: &ArcSExp,
    ) -> Result<Reduction<ArcSExp>, EvalErr<ArcSExp>> {
        let node = Node::new(allocator, argument_list.clone());
        self.nol.operator_handler(op, &node)
    }
}

impl<'p> INativeOpLookup<ArcAllocator> {
    pub fn operator_handler(
        &self,
        op: &[u8],
        argument_list: &Node<'p, ArcAllocator>,
    ) -> Result<
        Reduction<<ArcAllocator as Allocator>::Ptr>,
        EvalErr<<ArcAllocator as Allocator>::Ptr>,
    >
    where
        Node<'p, ArcAllocator>: ToPyObject,
    {
        if op.len() == 1 {
            if let Some(f) = self.f_lookup[op[0] as usize] {
                return f(argument_list);
            }
        }

        Python::with_gil(|py| {
            let pynode: PyObject = argument_list.to_object(py);
            let r1: PyResult<PyObject> = self.py_callback.call1(py, (op, pynode));
            let node = argument_list;

            match r1 {
                Err(pyerr) => {
                    let eval_err: PyResult<EvalErr<<ArcAllocator as Allocator>::Ptr>> = eval_err_for_pyerr(&node, py, &pyerr);
                    Err(unwrap_or_eval_err(eval_err, &node, "unexpected exception")?)
                }
                Ok(o) => {
                    let pair: &PyTuple =
                        unwrap_or_eval_err(o.extract(py), &node, "expected tuple")?;
                    let i0: u32 =
                        unwrap_or_eval_err(pair.get_item(0).extract(), &node, "expected u32")?;
                    let node: <ArcAllocator as Allocator>::Ptr =
                        unwrap_or_eval_err(pair.get_item(1).extract(), &node, "expected node")?;
                    Ok(Reduction(i0, node))
                }
            }
        })
    }
}
