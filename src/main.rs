extern crate rustc_hex;
extern crate wasmi;

use rustc_hex::FromHex;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use sszt::yaml::to_ssz;
use std::env;
use std::fs::File;
use wasmi::memory_units::Pages;
use wasmi::{
    Error as InterpreterError, Externals, FuncInstance, FuncRef, ImportsBuilder, MemoryInstance,
    MemoryRef, Module, ModuleImportResolver, ModuleInstance, NopExternals, RuntimeArgs,
    RuntimeValue, Signature, Trap, ValueType,
};

mod types;
use crate::types::*;

const LOADPRESTATEROOT_FUNC_INDEX: usize = 0;
const BLOCKDATASIZE_FUNC_INDEX: usize = 1;
const BLOCKDATACOPY_FUNC_INDEX: usize = 2;
const SAVEPOSTSTATEROOT_FUNC_INDEX: usize = 3;
const PUSHNEWDEPOSIT_FUNC_INDEX: usize = 4;
const EXECCODE_FUNC_INDEX: usize = 5;

struct Runtime<'a> {
    pub memory: Option<MemoryRef>,
    pre_state: &'a Bytes32,
    block_data: &'a ShardBlockBody,
    post_state: Bytes32,
}

impl<'a> Runtime<'a> {
    fn new(pre_state: &'a Bytes32, block_data: &'a ShardBlockBody) -> Runtime<'a> {
        Runtime {
            memory: Some(MemoryInstance::alloc(Pages(1), Some(Pages(1))).unwrap()),
            pre_state: pre_state,
            block_data: block_data,
            post_state: Bytes32::default(),
        }
    }

    fn get_post_state(&self) -> Bytes32 {
        self.post_state
    }
}

impl<'a> Externals for Runtime<'a> {
    fn invoke_index(
        &mut self,
        index: usize,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, Trap> {
        match index {
            LOADPRESTATEROOT_FUNC_INDEX => {
                let ptr: u32 = args.nth(0);
                println!("loadprestateroot to {}", ptr);

                // TODO: add checks for out of bounds access
                let memory = self.memory.as_ref().expect("expects memory");
                memory.set(ptr, &self.pre_state.bytes).unwrap();

                Ok(None)
            }
            SAVEPOSTSTATEROOT_FUNC_INDEX => {
                let ptr: u32 = args.nth(0);
                println!("savepoststateroot from {}", ptr);

                // TODO: add checks for out of bounds access
                let memory = self.memory.as_ref().expect("expects memory");
                memory.get_into(ptr, &mut self.post_state.bytes).unwrap();

                Ok(None)
            }
            BLOCKDATASIZE_FUNC_INDEX => {
                let ret: i32 = self.block_data.data.len() as i32;
                println!("blockdatasize {}", ret);
                Ok(Some(ret.into()))
            }
            BLOCKDATACOPY_FUNC_INDEX => {
                let ptr: u32 = args.nth(0);
                let offset: u32 = args.nth(1);
                let length: u32 = args.nth(2);
                println!(
                    "blockdatacopy to {} from {} for {} bytes",
                    ptr, offset, length
                );

                // TODO: add overflow check
                let offset = offset as usize;
                let length = length as usize;

                // TODO: add checks for out of bounds access
                let memory = self.memory.as_ref().expect("expects memory");
                memory
                    .set(ptr, &self.block_data.data[offset..length])
                    .unwrap();

                Ok(None)
            }
            PUSHNEWDEPOSIT_FUNC_INDEX => unimplemented!(),
            EXECCODE_FUNC_INDEX => {
                let ptr: u32 = args.nth(0);
                let length: u32 = args.nth(1);

                println!("EEI execute_code at {} for {} bytes", ptr, length);

                // TODO: add overflow check
                let length = length as usize;

                // TODO: add checks for out of bounds access
                let memory = self.memory.as_ref().expect("expects memory");
                let code = memory.get(ptr, length).unwrap();

                let (post_state, deposits) =
                    execute_code(&code, self.pre_state, &ShardBlockBody { data: vec![] });

                println!("post state: {:?}, deposits: {:?}", post_state, deposits);

                Ok(None)
            }
            _ => panic!("unknown function index"),
        }
    }
}

struct RuntimeModuleImportResolver;

impl<'a> ModuleImportResolver for RuntimeModuleImportResolver {
    fn resolve_func(
        &self,
        field_name: &str,
        _signature: &Signature,
    ) -> Result<FuncRef, InterpreterError> {
        let func_ref = match field_name {
            "eth2_loadPreStateRoot" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32][..], None),
                LOADPRESTATEROOT_FUNC_INDEX,
            ),
            "eth2_blockDataSize" => FuncInstance::alloc_host(
                Signature::new(&[][..], Some(ValueType::I32)),
                BLOCKDATASIZE_FUNC_INDEX,
            ),
            "eth2_blockDataCopy" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32, ValueType::I32, ValueType::I32][..], None),
                BLOCKDATACOPY_FUNC_INDEX,
            ),
            "eth2_savePostStateRoot" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32][..], None),
                SAVEPOSTSTATEROOT_FUNC_INDEX,
            ),
            "eth2_pushNewDeposit" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32][..], None),
                PUSHNEWDEPOSIT_FUNC_INDEX,
            ),
            "eth2_execCode" => FuncInstance::alloc_host(
                Signature::new(&[ValueType::I32, ValueType::I32][..], None),
                EXECCODE_FUNC_INDEX,
            ),
            _ => {
                return Err(InterpreterError::Function(format!(
                    "host module doesn't export function with name {}",
                    field_name
                )))
            }
        };
        Ok(func_ref)
    }
}

const BYTES_PER_SHARD_BLOCK_BODY: usize = 16384;
const ZERO_HASH: Bytes32 = Bytes32 { bytes: [0u8; 32] };

/// These are Phase 0 structures.
/// https://github.com/ethereum/eth2.0-specs/blob/dev/specs/core/0_beacon-chain.md
#[derive(Default, PartialEq, Clone, Debug)]
pub struct Deposit {}

/// These are Phase 2 Proposal 2 structures.

#[derive(Default, PartialEq, Clone, Debug)]
pub struct ExecutionScript {
    code: Vec<u8>,
}

#[derive(Default, PartialEq, Clone, Debug)]
pub struct BeaconState {
    execution_scripts: Vec<ExecutionScript>,
}

/// Shards are Phase 1 structures.
/// https://github.com/ethereum/eth2.0-specs/blob/dev/specs/core/1_shard-data-chains.md

#[derive(Default, PartialEq, Clone, Debug)]
pub struct ShardBlockHeader {}

#[derive(Default, PartialEq, Clone, Debug)]
pub struct ShardBlockBody {
    data: Vec<u8>,
}

#[derive(Default, PartialEq, Clone, Debug)]
pub struct ShardBlock {
    env: u64, // This is added by Phase 2 Proposal 2
    data: ShardBlockBody,
    // TODO: add missing fields
}

#[derive(Default, PartialEq, Clone, Debug)]
pub struct ShardState {
    exec_env_states: Vec<Bytes32>,
    slot: u64,
    parent_block: ShardBlockHeader,
    // TODO: add missing field
    // latest_state_roots: [bytes32, LATEST_STATE_ROOTS_LEMGTH]
}

pub fn execute_code(
    code: &[u8],
    pre_state: &Bytes32,
    block_data: &ShardBlockBody,
) -> (Bytes32, Vec<Deposit>) {
    println!(
        "Executing codesize({}) and data: {:#?}",
        code.len(),
        block_data
    );

    let module = Module::from_buffer(&code).unwrap();
    let mut imports = ImportsBuilder::new();
    // FIXME: use eth2
    imports.push_resolver("env", &RuntimeModuleImportResolver);

    let instance = ModuleInstance::new(&module, &imports)
        .unwrap()
        .assert_no_start();

    let mut runtime = Runtime::new(pre_state, block_data);

    let internal_mem = instance
        .export_by_name("memory")
        .expect("Module expected to have 'memory' export")
        .as_memory()
        .cloned()
        .expect("'memory' export should be a memory");

    runtime.memory = Some(internal_mem);

    let result = instance
        .invoke_export("main", &[], &mut runtime)
        .expect("Executed 'main'");

    println!("Result: {:?}", result);
    println!("Execution finished");

    (runtime.get_post_state(), vec![Deposit {}])
}

pub fn process_shard_block(
    state: &mut ShardState,
    beacon_state: &BeaconState,
    block: Option<ShardBlock>,
) {
    // println!("Beacon state: {:#?}", beacon_state);
    println!("Executing block: {:#?}", block);

    println!("Pre-execution: {:#?}", state);

    // TODO: implement state root handling

    if let Some(block) = block {
        // The execution environment identifier
        let env = block.env as usize; // FIXME: usize can be 32-bit
        let code = &beacon_state.execution_scripts[env].code;

        // Set post states to empty for any holes
        // for x in 0..env {
        //     state.exec_env_states.push(ZERO_HASH)
        // }
        let pre_state = &state.exec_env_states[env];
        let (post_state, deposits) = execute_code(code, pre_state, &block.data);
        state.exec_env_states[env] = post_state
    }

    // TODO: implement state + deposit root handling

    println!("Post-execution: {:#?}", state)
}

fn load_file(filename: &str) -> Vec<u8> {
    use std::io::prelude::*;
    let mut file = File::open(filename).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    buf
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
enum TestDataValue {
    Ssz(String),
    Object(serde_yaml::Value),
}

impl TestDataValue {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            TestDataValue::Ssz(s) => s.from_hex().unwrap(),
            TestDataValue::Object(o) => to_ssz(serde_yaml::to_vec(&o).unwrap()),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestBeaconState {
    execution_scripts: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestShardBlock {
    env: u64,
    data: TestDataValue,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestShardState {
    exec_env_states: Vec<TestDataValue>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestFile {
    beacon_state: TestBeaconState,
    shard_blocks: Vec<TestShardBlock>,
    shard_pre_state: TestShardState,
    shard_post_state: TestShardState,
}

impl From<TestBeaconState> for BeaconState {
    fn from(input: TestBeaconState) -> Self {
        BeaconState {
            execution_scripts: input
                .execution_scripts
                .iter()
                .map(|x| ExecutionScript { code: load_file(x) })
                .collect(),
        }
    }
}

impl From<TestShardBlock> for ShardBlock {
    fn from(input: TestShardBlock) -> Self {
        ShardBlock {
            env: input.env,
            data: ShardBlockBody {
                data: input.data.to_bytes(),
            },
        }
    }
}

impl From<TestShardState> for ShardState {
    fn from(input: TestShardState) -> Self {
        ShardState {
            exec_env_states: input
                .exec_env_states
                .iter()
                .map(|x| {
                    let hash: Vec<u8> = match x {
                        TestDataValue::Ssz(_) => x.to_bytes(),
                        TestDataValue::Object(_) => Keccak256::digest(&x.to_bytes()[..])[..].into(),
                    };
                    assert!(hash.len() == 32);
                    let mut ret = Bytes32::default();
                    ret.bytes.copy_from_slice(&hash[..]);
                    ret
                })
                .collect(),
            slot: 0,
            parent_block: ShardBlockHeader {},
        }
    }
}

fn process_yaml_test(filename: &str) {
    println!("Process yaml!");
    let content = load_file(&filename);
    let test_file: TestFile = serde_yaml::from_slice::<TestFile>(&content[..]).unwrap();
    println!("{:#?}", test_file);

    let beacon_state: BeaconState = test_file.beacon_state.into();
    let pre_state: ShardState = test_file.shard_pre_state.into();
    let post_state: ShardState = test_file.shard_post_state.into();

    let mut shard_state = pre_state;
    for block in test_file.shard_blocks {
        process_shard_block(&mut shard_state, &beacon_state, Some(block.into()))
    }
    println!("{:#?}", shard_state);
    assert_eq!(shard_state, post_state);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    process_yaml_test(if args.len() != 2 {
        "test.yaml"
    } else {
        &args[1]
    });
}
