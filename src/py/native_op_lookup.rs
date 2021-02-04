use crate::allocator::Allocator;
use crate::node::Node;
use crate::reduction::{EvalErr, Reduction};

use super::arc_allocator::ArcSExp;
use super::f_table::{opcode_by_name, FLookup};
use super::py_node::PyNode;
use super::py_support::PythonSupport;

use pyo3::exceptions::PyBaseException;
use pyo3::prelude::*;
use pyo3::types::{PyString, PyTuple};

impl<A: Allocator> ToPyObject for Node<'_, A>
where
    A::Ptr: ToPyObject,
{
    fn to_object(&self, py: Python<'_>) -> PyObject {
        self.ptr().to_object(py)
    }
}

impl PythonSupport for ArcSExp {
    fn py_object_to_ptr(obj: &PyAny) -> PyResult<ArcSExp> {
        let sexp_ptr: PyNode = obj.extract()?;
        let node: ArcSExp = (&sexp_ptr as &PyNode).into();
        Ok(node)
    }
}

fn eval_err_for_pyerr<'p, A: Allocator, T: Clone>(
    _node: &Node<'_, A>,
    py: Python<'p>,
    pyerr: &'p PyErr,
) -> PyResult<EvalErr<T>>
where
    T: PythonSupport,
{
    let be: &PyBaseException = pyerr.pvalue(py);
    let sexp: &PyAny = be.getattr("_sexp")?;
    let node: PyResult<T> = T::py_object_to_ptr(sexp);
    let node = node?;

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

#[derive(Clone)]
pub struct INativeOpLookup<A: Allocator> {
    py_callback: PyObject,
    f_lookup: FLookup<A>,
}

impl<A: Allocator> INativeOpLookup<A> {
    pub fn new(unknown_op_callback: PyObject) -> Self {
        let f_lookup: FLookup<A> = [None; 256];
        INativeOpLookup {
            py_callback: unknown_op_callback,
            f_lookup,
        }
    }
    pub fn add_native(&mut self, opcode: u8, name: &str) -> PyResult<bool> {
        let f = opcode_by_name(name);
        self.f_lookup[opcode as usize] = f;
        Ok(f.is_some())
    }
}
impl<'p, A: Allocator<Ptr = P>, P: Clone> INativeOpLookup<A> {
    pub fn operator_handler(
        &self,
        op: &[u8],
        argument_list: &Node<'p, A>,
    ) -> Result<Reduction<P>, EvalErr<P>>
    where
        Node<'p, A>: ToPyObject,
        P: PythonSupport,
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
                    let eval_err: PyResult<EvalErr<P>> = eval_err_for_pyerr(&node, py, &pyerr);
                    let r: EvalErr<P> =
                        unwrap_or_eval_err(eval_err, &node, "unexpected exception")?;
                    Err(r)
                }
                Ok(o) => {
                    let py_any: PyResult<&PyAny> = o.extract(py);
                    let pair: &PyAny = unwrap_or_eval_err(py_any, &node, "expected tuple")?;
                    let pair: PyResult<&PyTuple> = pair.extract();
                    let pair: &PyTuple = unwrap_or_eval_err(pair, &node, "expected tuple")?;

                    let t: PyResult<u32> = pair.get_item(0).extract();
                    let i0: u32 = unwrap_or_eval_err(t, &node, "expected u32")?;

                    let t: PyResult<P> = P::py_object_to_ptr(pair.get_item(1));

                    let node: P = unwrap_or_eval_err(t, &node, "expected node")?;
                    Ok(Reduction(i0, node))
                }
            }
        })
    }
}
