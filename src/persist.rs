use pyo3::prelude::*;
use pyo3::FromPyPointer;
//use pyo3::{prelude::AsPyPointer};
use std::marker::PhantomData;

// we waste this many u32 entries in a vector so
// that we can easily see memory usage go up and down

const SIZE: usize = 1024 * 1024 * 100;

#[pyclass(unsendable)]
pub struct Persist {
    v: usize,
}

struct Foo<'a> {
    //val: Option<&'a u32>,
    //foo: Py<u32>,
    count: u32,
    wasted_space: Vec<u32>,
    phantom: PhantomData<&'a u32>,
}

fn junk(size: usize) -> Vec<u32> {
    let mut v: Vec<u32> = Vec::with_capacity(size);
    for i in 0..size {
        v.push(i as u32);
    }
    v
}

#[pymethods]
impl Persist {
    #[new]
    pub fn new<'p>(_py: Python<'p>, v: u32) -> Self {
        let obj = Box::new(Foo {
            count: v,
            wasted_space: junk(SIZE),
            phantom: PhantomData,
        });
        let foo_box = Box::into_raw(obj);
        Persist {
            v: foo_box as usize,
        }
    }

    pub fn count(&self, py: Python) -> u32 {
        let r = self.get_foo(py);
        r.wasted_space[r.count as usize]
    }

    pub fn bump(&mut self, py: Python) -> u32 {
        let mut r = self.get_foo_mut(py);
        let rv = r.count;
        r.count += 1;
        rv
    }
}

impl Persist {
    fn get_foo<'p>(&self, py: Python<'p>) -> &'p Foo<'p> {
        unsafe { std::mem::transmute(self.v) }
    }

    fn get_foo_mut<'p>(&mut self, py: Python<'p>) -> &'p mut Foo<'p> {
        unsafe { std::mem::transmute(self.v) }
    }
}

impl Drop for Persist {
    fn drop(&mut self) {
        println!("dropping");
        let _b = unsafe { Box::from_raw(self.v as *mut Foo) };
    }
}
