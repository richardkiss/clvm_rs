/**
 * This currently isn't used. It's intended to be an allocator that uses python
 * objects as its paramaterized `T` pointer type.
 */
//use aovec::Aovec;
//use lazy_static::*;
//use std::cell::RefCell;
//use std::sync::Arc;
use pyo3::exceptions::PyValueError;
//use pyo3::ffi::PyBytes_FromStringAndSize;
use pyo3::ffi::Py_IncRef;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};
use pyo3::AsPyPointer;

use crate::allocator::{Allocator, SExp};

use super::to_py_node::ToPyNode;

/*
static NULL_BYTES: [u8; 0] = [];
static ONE_BYTES: [u8; 1] = [1];

lazy_static! {
    static ref NULL: Box<[u8]> = Box::new(NULL_BYTES);
    static ref ONE: Box<[u8]> = Box::new(ONE_BYTES);
}
*/

#[pyclass(subclass, unsendable)]
#[derive(Clone)]
pub struct PyNode {
    node: PySExp,
}

impl From<PyNode> for PySExp {
    fn from(node: PyNode) -> Self {
        node.node
    }
}

impl From<&PyNode> for PySExp {
    fn from(node: &PyNode) -> Self {
        node.clone().into()
    }
}

impl From<PySExp> for PyNode {
    fn from(node: PySExp) -> Self {
        PyNode { node }
    }
}

impl From<&PySExp> for PyNode {
    fn from(node: &PySExp) -> Self {
        node.clone().into()
    }
}

#[derive(Clone)]
pub enum PySExp {
    // for Atom we use PyBytes as a pyo3::ffi::PyObject
    Atom(*mut pyo3::ffi::PyObject),
    // for Pair we use the children, but also extract the children for quicker access
    //Pair(Arc<(RefCell<Option<PyObject>>, PyCell<PyNode>, PyCell<PyNode>)>),
    // TODO BRAIN DAMAGE TK
    Pair(*mut pyo3::ffi::PyObject),
}

fn build_tuple<'p>(py: Python<'p>, p1: &PyAny, p2: &PyAny) -> &'p PyTuple {
    let pair: [&PyAny; 2] = [p1, p2];
    let iter: std::slice::Iter<&PyAny> = pair.iter();
    PyTuple::new(py, iter)
}

impl From<&PySExp> for *mut pyo3::ffi::PyObject {
    fn from(p: &PySExp) -> Self {
        match p.clone() {
            PySExp::Atom(p) => p,
            PySExp::Pair(p) => p,
        }
    }
}

impl<'p> Allocator for Python<'p> {
    type Ptr = PySExp;

    fn new_atom(&self, v: &[u8]) -> PySExp {
        let pybytes: &PyBytes = PyBytes::new(*self, &v);
        let py_obj: *mut pyo3::ffi::PyObject = pybytes.as_ptr();
        PySExp::Atom(py_obj)
    }

    fn new_pair(&self, p1: &PySExp, p2: &PySExp) -> PySExp {
        let p1: *mut pyo3::ffi::PyObject = p1.into();
        let p2: *mut pyo3::ffi::PyObject = p2.into();

        let p1: &PyAny =
            unsafe { pyo3::conversion::FromPyPointer::from_owned_ptr_or_panic(*self, p1) };
        let p2: &PyAny =
            unsafe { pyo3::conversion::FromPyPointer::from_owned_ptr_or_panic(*self, p2) };

        let tuple: &PyTuple = build_tuple(*self, p1, p2);
        let obj: *mut pyo3::ffi::PyObject = tuple.as_ptr();
        PySExp::Pair(obj)
    }

    fn sexp<'a: 'c, 'b: 'c, 'c>(&'a self, node: &'b PySExp) -> SExp<'c, PySExp> {
        match node {
            PySExp::Atom(py_bytes) => {
                let pb: &PyBytes = unsafe {
                    pyo3::conversion::FromPyPointer::from_owned_ptr_or_panic(*self, *py_bytes)
                };
                let v1: &[u8] = pb.as_bytes();
                SExp::Atom(v1)
            }
            PySExp::Pair(py_tuple) => {
                let pt: &PyTuple = unsafe {
                    pyo3::conversion::FromPyPointer::from_borrowed_ptr_or_panic(*self, *py_tuple)
                };
                let i0: &PyAny = pt.get_item(0);
                let i1: &PyAny = pt.get_item(1);
                let left: PyRef<'_, PyNode> = extract_node(*self, i0).unwrap();
                let right: PyRef<'_, PyNode> = extract_node(*self, i1).unwrap();
                let left: PySExp = left.node.clone();
                let right: PySExp = right.node.clone();
                SExp::Pair(left, right)
            }
        }
    }

    fn null(&self) -> PySExp {
        self.new_atom(&[])
    }

    fn one(&self) -> PySExp {
        self.new_atom(&[1])
    }
}

fn extract_atom<'p>(_py: &Python<'p>, obj: &PyAny) -> PyResult<PyNode> {
    let py_bytes: &PyBytes = obj.extract()?;
    let o: *mut pyo3::ffi::PyObject = py_bytes.as_ptr();
    unsafe { Py_IncRef(o) };
    Ok(PySExp::Atom(o).into())
}

fn extract_node<'a>(_py: Python, obj: &'a PyAny) -> PyResult<PyRef<'a, PyNode>> {
    let ps: &PyCell<PyNode> = obj.downcast()?;
    let node: PyRef<'a, PyNode> = ps.try_borrow()?;
    Ok(node)
}

fn extract_tuple<'a>(
    py: &Python,
    obj: &'a PyAny,
) -> PyResult<(PyNode, PyRef<'a, PyNode>, PyRef<'a, PyNode>)> {
    println!("1");
    let v: &PyTuple = obj.downcast()?;
    println!("2");
    if v.len() != 2 {
        return Err(PyValueError::new_err("SExp tuples must be size 2"));
    }
    println!("3");
    let i0: &PyAny = v.get_item(0);
    println!("4");
    let i1: &PyAny = v.get_item(1);
    println!("5");
    let left = extract_node(*py, i0)?;
    println!("6");
    let right = extract_node(*py, i1)?;
    println!("7");

    let o: *mut pyo3::ffi::PyObject = obj.as_ptr();
    unsafe { Py_IncRef(o) };
    Ok((PySExp::Pair(o).into(), left, right))
}

#[pymethods]
impl PyNode {
    #[new]
    pub fn py_new(py: Python, obj: &PyAny) -> PyResult<Self> {
        let node: PyNode = {
            println!("About to extract atom");
            let n = extract_atom(&py, obj);
            if let Ok(r) = n {
                println!("Did extract atom");
                r
            } else {
                println!("Did NOT extract atom");

                let (node, _left, _right) = extract_tuple(&py, obj)?;
                node
            }
        };
        println!("bar");
        Ok(node)
    }

    #[getter(atom)]
    pub fn atom(&self, py: Python) -> Option<PyObject> {
        match self.node {
            PySExp::Atom(ffi_pyobj) => {
                let t: *mut pyo3::ffi::PyObject = ffi_pyobj;
                let pb: &PyBytes =
                    unsafe { pyo3::conversion::FromPyPointer::from_borrowed_ptr_or_panic(py, t) };
                Some(pb.to_object(py))
            }
            _ => None,
        }
    }

    #[getter(pair)]
    pub fn pair(&self, py: Python) -> Option<PyObject> {
        match self.node {
            PySExp::Pair(ffi_pyobj) => {
                let t: *mut pyo3::ffi::PyObject = ffi_pyobj;
                let pb: &PyTuple =
                    unsafe { pyo3::conversion::FromPyPointer::from_borrowed_ptr_or_panic(py, t) };
                Some(pb.to_object(py))
            }
            _ => None,
        }
    }
}

impl<'s> FromPyObject<'s> for PySExp {
    fn extract(obj: &'s PyAny) -> PyResult<Self> {
        let pn: PyNode = obj.extract()?;
        Ok(pn.node)
    }
}

impl<'p> ToPyNode<PyNode> for Python<'p> {
    fn to_pynode(&self, ptr: &Self::Ptr) -> PyNode {
        PyNode { node: ptr.clone() }
    }
}

impl ToPyObject for PySExp {
    fn to_object(&self, py: Python<'_>) -> PyObject {
        let pynode: PyNode = self.into();
        let pynode: &PyCell<PyNode> = PyCell::new(py, pynode).unwrap();
        let pa: &PyAny = &pynode;
        pa.to_object(py)
    }
}

impl IntoPy<PyObject> for PySExp {
    fn into_py(self, py: Python) -> PyObject {
        let py_node: PyNode = self.into();
        let py_cell: &PyCell<PyNode> = PyCell::new(py, py_node).unwrap();
        let py_any: &PyAny = &py_cell;
        py_any.into()
    }
}
