//!
//! This is an example Phase 2 script called "Bazaar".
//!
//! The "state" consists of an append-only list of messages. Each transaction
//! has to supply the new list of messages to be appended, as well as the entire
//! current state. The hash of the SSZ encoded state is stored as the "state root".
//! Obviously this has an unsustainable growth, but the main point is to demonstrate
//! how to work with SSZ serialised data.
//!
//! It doesn't yet use SSZ merkleization and SSZ partial, that should be an obvious next step.
//!
//! Message
//! {
//!    "timestamp": uint64,
//!    "message": bytes
//! }
//!
//! State {
//!    "messages": [Message]
//! }
//!
//! InputBlock {
//!    "new_messages": [Message],
//!    "state": State
//! }
//!
#[cfg(not(test))]
use ewasm_api::*;
use merkle_partial::{Partial, Path, SerializedPartial};
use ssz::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use typenum::{U32, U8};

#[derive(
    Clone,
    Debug,
    PartialEq,
    ssz_derive::Encode,
    ssz_derive::Decode,
    merkle_partial_derive::Partial,
    Default,
)]
struct Message {
    pub timestamp: u64,
    pub message: FixedVector<u8, U32>,
}

// `State` merkle tree representation
//
//                      root ------+
//                     /            \
//             +----- 1 -----+       2   <-- length
//            /               \
//           3                 4
//        /     \           /     \
//       7       8         9       10
//     /   \   /   \     /   \   /   \
//    15   16 17   18   19   20 21   22  <-- messages
#[derive(
    Debug,
    PartialEq,
    ssz_derive::Encode,
    ssz_derive::Decode,
    merkle_partial_derive::Partial,
    Default,
)]
struct State {
    pub messages: VariableList<Message, U8>,
}

#[derive(Clone, Debug, PartialEq, ssz_derive::Encode, ssz_derive::Decode, Default)]
struct InputBlock {
    pub new_messages: Vec<Message>,
    pub state: SerializedPartial,
}

#[cfg(not(test))]
fn process_block(pre_state_root: types::Bytes32, block_data: &[u8]) -> types::Bytes32 {
    let block = InputBlock::from_ssz_bytes(&block_data).expect("valid input");

    let mut partial: Partial<State> = Partial::<State>::new(block.state);
    assert_eq!(partial.fill(), Ok(()));
    assert_eq!(partial.root().unwrap(), &pre_state_root.bytes.to_vec());

    // add new messages to state
    for (i, msg) in block.new_messages.iter().enumerate() {
        // set timestamp
        assert_eq!(
            partial.set_bytes(
                vec![
                    Path::Ident("messages".to_string()),
                    Path::Index(i as u64),
                    Path::Ident("timestamp".to_string()),
                ],
                msg.timestamp.as_ssz_bytes(),
            ),
            Ok(())
        );

        // set message
        for j in 0..32 {
            let path = vec![
                Path::Ident("messages".to_string()),
                Path::Index(i as u64),
                Path::Ident("message".to_string()),
                Path::Index(j),
            ];

            let bytes = vec![msg.message.as_ssz_bytes()[j as usize]];

            assert_eq!(partial.set_bytes(path, bytes), Ok(()));
        }
    }

    // set length
    let mut len = vec![0; 32];
    len[0] = block.new_messages.len() as u8;
    assert_eq!(
        partial.set_bytes(
            vec![
                Path::Ident("messages".to_string()),
                Path::Ident("len".to_string())
            ],
            len.clone(),
        ),
        Ok(())
    );

    // recalculate the root
    assert_eq!(partial.refresh(), Ok(()));

    let mut ret = types::Bytes32::default();
    ret.bytes.copy_from_slice(&partial.root().unwrap()[0..32]);

    ret
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn main() {
    let pre_state_root = eth2::load_pre_state_root();
    let block_data = eth2::acquire_block_data();
    let post_state_root = process_block(pre_state_root, &block_data);
    eth2::save_post_state_root(post_state_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_partial::cache::hash_children;

    fn zero_hash(depth: u8) -> Vec<u8> {
        if depth == 0 {
            vec![0; 32]
        } else if depth == 1 {
            hash_children(&[0; 32], &[0; 32])
        } else {
            let last = zero_hash(depth - 1);
            hash_children(&last, &last)
        }
    }

    #[test]
    fn generate_pre_state_root() {
        // The data tree has a height of 4 and then the length is mixed in
        println!(
            "pre-state root: {:?}",
            hash_children(&zero_hash(4), &zero_hash(0))
        );
        println!(
            "pre-state root (hex): {:?}",
            hex::encode(hash_children(&zero_hash(4), &zero_hash(0)))
        );
    }

    #[test]
    fn generate_input_block() {
        let mut block = InputBlock::default();
        block.new_messages.push(Message {
            timestamp: 1,
            message: FixedVector::new(vec![1; 32]).unwrap(),
        });

        block.new_messages.push(Message {
            timestamp: 2,
            message: FixedVector::new(vec![42; 32]).unwrap(),
        });
        let mut arr = vec![0; 224];
        arr[128..160].copy_from_slice(&zero_hash(2));
        arr[160..192].copy_from_slice(&zero_hash(3));
        block.state = SerializedPartial {
            indices: vec![31, 32, 33, 34, 8, 4, 2],
            chunks: arr.clone(),
        };

        println!("block: {:?}", block.as_ssz_bytes());
        println!("block (hex): {:?}", hex::encode(block.as_ssz_bytes()));
    }

    #[test]
    fn from_scratch() {
        // generated input block
        let data = vec![
            8, 0, 0, 0, 88, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 42,
            42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
            42, 42, 42, 42, 42, 42, 42, 42, 42, 8, 0, 0, 0, 64, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0,
            32, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0,
            0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 219, 86, 17, 78, 0, 253, 212, 193, 248, 92, 137, 43, 243, 90, 201, 168, 146,
            137, 170, 236, 177, 235, 208, 169, 108, 222, 96, 106, 116, 139, 93, 113, 199, 128, 9,
            253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228,
            76, 75, 193, 95, 244, 205, 16, 90, 179, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let mut block = InputBlock::from_ssz_bytes(&data).expect("valid input");
        let mut partial: Partial<State> = Partial::<State>::new(block.state);
        assert_eq!(partial.fill(), Ok(()));
        assert_eq!(
            hex::encode(partial.root().unwrap()),
            "792930bbd5baac43bcc798ee49aa8185ef76bb3b44ba62b91d86ae569e4bb535"
        );

        for (i, msg) in block.new_messages.iter().enumerate() {
            // set timestamp
            assert_eq!(
                partial.set_bytes(
                    vec![
                        Path::Ident("messages".to_string()),
                        Path::Index(i as u64),
                        Path::Ident("timestamp".to_string()),
                    ],
                    msg.timestamp.as_ssz_bytes(),
                ),
                Ok(())
            );

            // set message
            for j in 0..32 {
                let path = vec![
                    Path::Ident("messages".to_string()),
                    Path::Index(i as u64),
                    Path::Ident("message".to_string()),
                    Path::Index(j),
                ];

                let bytes = vec![msg.message.as_ssz_bytes()[j as usize]];

                assert_eq!(partial.set_bytes(path, bytes), Ok(()));
            }
        }

        // set length
        let mut len = vec![0; 32];
        len[0] = 2;
        assert_eq!(
            partial.set_bytes(
                vec![
                    Path::Ident("messages".to_string()),
                    Path::Ident("len".to_string())
                ],
                len.clone(),
            ),
            Ok(())
        );

        assert_eq!(partial.refresh(), Ok(()));
        println!("partial raw: {:?}", partial);

        println!("post-state root: {:?}", partial.root().unwrap());
        println!(
            "post-state root (hex): {:?}",
            hex::encode(partial.root().unwrap())
        );

        // Values from partial.cache() after refresh
        //
        // 31:[  1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0],
        // 32:[  1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1],
        // 33:[  2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0],
        // 34:[ 42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42,  42],
        //
        // 15:[ 36,  60,  96,  31,  17, 173,  87, 198,  22, 149, 138, 232, 200, 147,   5, 228, 175,   2,  31, 117,  94, 167, 243, 198, 113,  63,  32, 118, 134,  81, 181, 112],
        // 16:[ 84, 135,  16,  58, 160, 192,   3, 177,  34, 136, 117,  47, 172,  73, 102, 138,   4, 234, 252, 243,  31,   2,  89, 125, 141,   9,   6,  55,  22, 147, 247, 135],
        //
        // 7: [118, 124,  81, 189,  61, 143, 145,  42,  88, 251,  68, 252, 223, 102,  21,  56,  51,  68,  84, 139, 204,  72,  36,  30, 109, 186, 241,  14, 177, 192, 206, 148],
        // 8: [219,  86,  17,  78,   0, 253, 212, 193, 248,  92, 137,  43, 243,  90, 201, 168, 146, 137, 170, 236, 177, 235, 208, 169, 108, 222,  96, 106, 116, 139,  93, 113],
        //
        // 3: [111, 127, 234,  26, 228, 169, 244, 177,  31, 220,  77,  64,  34, 233, 207,  79, 144, 124, 108,  31, 229,  46, 194, 200,  55, 168, 170, 140, 205, 221, 194,  77],
        // 4: [199, 128,   9, 253, 240, 127, 197, 106,  17, 241,  34,  55,   6,  88, 163,  83, 170, 165,  66, 237,  99, 228,  76,  75, 193,  95, 244, 205,  16,  90, 179,  60],

        // 1: [173, 195,  23, 133, 252, 215, 239, 130, 254, 131,  70,  87, 124, 233, 151, 238, 186,  27, 252, 146,  86, 211, 190,  13, 105,  39, 127, 253, 126, 122,  79,  45],
        // 2:[  2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0],

        // need 31, 32, 33, 34, 8, 4, 2
        let one = zero_hash(4);
        let two = vec![0; 32];
        let root = hash_children(&one, &two);
        println!("hand-calculated pre-root: {:?}", hex::encode(root));

        // need 31, 32, 33, 34, 8, 4, 2
        let thirty_one = vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let thirty_two = vec![
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1,
        ];

        let thirty_three = vec![
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let thirty_four = vec![
            42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
            42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
        ];

        let eight = zero_hash(2);
        let four = zero_hash(3);
        let mut two = vec![0; 32];
        two[0] = 2;

        // calculate hashes
        let fifteen = hash_children(&thirty_one, &thirty_two);
        let sixteen = hash_children(&thirty_three, &thirty_four);
        let seven = hash_children(&fifteen, &sixteen);
        let three = hash_children(&seven, &eight);
        let one = hash_children(&three, &four);
        let root = hash_children(&one, &two);

        println!("hand-calculated post-root: {:?}", hex::encode(root));
    }
}
