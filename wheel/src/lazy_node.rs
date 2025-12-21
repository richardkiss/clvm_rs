use clvmr::allocator::{Allocator, NodePtr, SExp};
use clvmr::serde::serialize_2026;
use std::rc::Rc;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};

#[pyclass(subclass, unsendable)]
#[derive(Clone)]
pub struct LazyNode {
    allocator: Rc<Allocator>,
    node: NodePtr,
}

impl ToPyObject for LazyNode {
    fn to_object(&self, py: Python<'_>) -> PyObject {
        let node: Bound<LazyNode> = Bound::new(py, self.clone()).unwrap();
        node.to_object(py)
    }
}

#[pymethods]
impl LazyNode {
    #[getter(pair)]
    pub fn pair(&self, py: Python) -> PyResult<Option<PyObject>> {
        match &self.allocator.sexp(self.node) {
            SExp::Pair(p1, p2) => {
                let r1 = Self::new(self.allocator.clone(), *p1);
                let r2 = Self::new(self.allocator.clone(), *p2);
                let v = PyTuple::new_bound(py, &[r1, r2]);
                Ok(Some(v.into()))
            }
            _ => Ok(None),
        }
    }

    #[getter(atom)]
    pub fn atom(&self, py: Python) -> Option<PyObject> {
        match &self.allocator.sexp(self.node) {
            SExp::Atom => {
                Some(PyBytes::new_bound(py, self.allocator.atom(self.node).as_ref()).into())
            }
            _ => None,
        }
    }

    /// Serialize this node using the 2026 serialization format.
    ///
    /// This method:
    /// 1. Interns the node to deduplicate atoms and pairs
    /// 2. Renumbers atoms and pairs for optimal compression
    /// 3. Serializes using the 2026 format with varints
    ///
    /// Returns:
    ///     bytes: The serialized representation
    pub fn serialize_2026(&self, py: Python) -> PyResult<PyObject> {
        let serialized = serialize_2026(&self.allocator, self.node)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new_bound(py, &serialized).into())
    }
}

impl LazyNode {
    pub const fn new(a: Rc<Allocator>, n: NodePtr) -> Self {
        Self {
            allocator: a,
            node: n,
        }
    }
}
