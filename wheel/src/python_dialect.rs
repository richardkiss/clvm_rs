// import `Map`
use pyo3::prelude::*;
use std::collections::{HashMap, HashSet};

use clvmr::allocator::{Allocator, NodePtr};
use clvmr::bls_ops::{
    op_bls_g1_multiply, op_bls_g1_negate, op_bls_g1_subtract, op_bls_g2_add, op_bls_g2_multiply,
    op_bls_g2_negate, op_bls_g2_subtract, op_bls_map_to_g1, op_bls_map_to_g2,
    op_bls_pairing_identity, op_bls_verify,
};
use clvmr::core_ops::{op_cons, op_eq, op_first, op_if, op_listp, op_raise, op_rest};
use clvmr::cost::Cost;
use clvmr::dialect::{Dialect, OperatorSet};
use clvmr::err_utils::err;
use clvmr::more_ops::{
    op_add, op_all, op_any, op_ash, op_coinid, op_concat, op_div, op_divmod, op_gr, op_gr_bytes,
    op_logand, op_logior, op_lognot, op_logxor, op_lsh, op_mod, op_modpow, op_multiply, op_not,
    op_point_add, op_pubkey_for_exp, op_sha256, op_strlen, op_substr, op_subtract,
};
use clvmr::reduction::{Reduction, Response};
use clvmr::secp_ops::{op_secp256k1_verify, op_secp256r1_verify};
use clvmr::serde::{node_from_bytes_backrefs_record, node_to_bytes_backrefs};

type OpFn = fn(&mut Allocator, NodePtr, Cost) -> Response;
fn op_unknown(_allocator: &mut Allocator, args: NodePtr, _max_cost: Cost) -> Response {
    err(args, "unknown operator")
}

pub struct PythonDialect<'py> {
    small_ops: [OpFn; 255],
    large_ops: HashMap<u32, OpFn>,
    quote_kw: u32,
    apply_kw: u32,
    softfork_kw: u32,
    custom_op_callback: Bound<'py, PyAny>, //fn(&mut Allocator, NodePtr, Cost, u32) -> Response,
    custom_op_set: HashSet<u32>,
}

impl<'py> PythonDialect<'py> {
    pub fn new(
        custom_op_callback: Bound<'py, PyAny>, //fn(&mut Allocator, NodePtr, Cost, u32) -> Response,
        custom_op_list: Vec<u32>,
    ) -> Self {
        let quote_kw = 1;
        let apply_kw = 2;
        let softfork_kw = 36;
        let mut large_ops = HashMap::new();
        for (opcode, f) in LARGE_OPS_DEFAULT.iter() {
            large_ops.insert(*opcode, *f);
        }
        let mut small_ops: [OpFn; 255] = [op_unknown; 255];
        for (i, f) in SMALL_OPS_DEFAULT.iter().enumerate() {
            small_ops[i] = *f;
        }
        let custom_op_set: HashSet<u32> = custom_op_list.into_iter().collect();
        PythonDialect {
            small_ops,
            large_ops,
            quote_kw,
            apply_kw,
            softfork_kw,
            custom_op_callback,
            custom_op_set,
        }
    }
}

const LARGE_OPS_DEFAULT: [(u32, OpFn); 2] = [
    (0x13d61f00, op_secp256k1_verify),
    (0x1c3a8f00, op_secp256r1_verify),
];

const SMALL_OPS_DEFAULT: [OpFn; 62] = [
    op_unknown,
    op_unknown,
    op_if,
    op_cons,
    op_first,
    op_rest,
    op_listp,
    op_raise,
    op_eq,
    op_gr_bytes,
    op_sha256, // 10
    op_substr,
    op_strlen,
    op_concat,
    op_unknown,
    op_add,
    op_subtract,
    op_multiply,
    op_div,
    op_divmod,
    op_gr, // 20
    op_ash,
    op_lsh,
    op_logand,
    op_logior,
    op_logxor,
    op_lognot,
    op_unknown,
    op_point_add,
    op_pubkey_for_exp,
    op_unknown, // 30
    op_not,
    op_any,
    op_all, // 33
    op_unknown,
    op_unknown,
    op_unknown,
    op_unknown,
    op_unknown,
    op_unknown,
    op_unknown, // 40
    op_unknown,
    op_unknown,
    op_unknown,
    op_unknown,
    op_unknown,
    op_unknown,
    op_unknown,
    op_coinid, // 48
    op_bls_g1_subtract,
    op_bls_g1_multiply,
    op_bls_g1_negate,
    op_bls_g2_add,
    op_bls_g2_subtract,
    op_bls_g2_multiply,
    op_bls_g2_negate,
    op_bls_map_to_g1,
    op_bls_map_to_g2,
    op_bls_pairing_identity,
    op_bls_verify,
    op_modpow,
    op_mod,
];

fn call_into_python<'py>(
    allocator: &mut Allocator,
    argument_list: NodePtr,
    max_cost: Cost,
    custom_op_callback: &Bound<'py, PyAny>,
    custom_op: u32,
) -> Response {
    let serialized_node = node_to_bytes_backrefs(allocator, argument_list).unwrap();
    let r: Vec<u8> = custom_op_callback
        .call1((serialized_node, max_cost, custom_op))
        .unwrap()
        .extract()
        .unwrap();

    let new_node: (NodePtr, HashSet<NodePtr>) =
        node_from_bytes_backrefs_record(allocator, &r).unwrap();
    let np: NodePtr = new_node.0;
    let cost: Cost = max_cost;
    let red: Reduction = Reduction(cost, np);

    let r: Response = Ok(red);
    r
}

impl<'py> Dialect for PythonDialect<'py> {
    fn op(
        &self,
        allocator: &mut Allocator,
        o: NodePtr,
        argument_list: NodePtr,
        max_cost: Cost,
        _extension: OperatorSet,
    ) -> Response {
        if let Some(opcode) = allocator.small_number(o) {
            if self.custom_op_set.contains(&opcode) {
                return call_into_python(
                    allocator,
                    argument_list,
                    max_cost,
                    &self.custom_op_callback,
                    opcode,
                );
            }

            if opcode < 256 {
                let f = self.small_ops[opcode as usize];
                return f(allocator, argument_list, max_cost);
            }

            let f = self.large_ops.get(&opcode);
            if let Some(f) = f {
                return f(allocator, argument_list, max_cost);
            }
        }
        op_unknown(allocator, argument_list, max_cost)
    }

    fn quote_kw(&self) -> u32 {
        self.quote_kw
    }
    fn apply_kw(&self) -> u32 {
        self.apply_kw
    }
    fn softfork_kw(&self) -> u32 {
        self.softfork_kw
    }
    fn softfork_extension(&self, _: u32) -> OperatorSet {
        OperatorSet::Default
    }
    fn allow_unknown_ops(&self) -> bool {
        false
    }
}
