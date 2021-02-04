use pyo3::prelude::*;

pub trait PythonSupport: Sized {
    fn py_object_to_ptr(obj: &PyAny) -> PyResult<Self>;
}
