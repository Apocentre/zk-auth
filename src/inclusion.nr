use dep::std;
use dep::collections::dynamic_array::DynamicArray;
use dep::base64::{
  encoder::Encoder, classic::get_padding_char,
  constants::{MAX_ENCODED_SIZE},
};
use crate::constants::{MAX_CLAIM_LEN, MAX_JWT_LEN, SIG_LEN, NON_ASCII_CODE};

fn get_slice(array: [Field; MAX_JWT_LEN], start: u64) -> DynamicArray<Field, MAX_ENCODED_SIZE> {
  let mut slice = DynamicArray::init();

  for i in 0..MAX_ENCODED_SIZE as u64 {
    let index = start + i;
    slice.push(array[index]);
  }

  slice
}

/// The function will encode the given claim value and will
/// check that the bytes of the encoded value are part of the longer jwt base64 encoded token.
/// In essence, the function checks that the given claim is part of the jwt token
pub fn prove_inclusion(
  claim: [Field; MAX_CLAIM_LEN],
  jwt: [Field; MAX_JWT_LEN],
  start_index: u64,
  has_padding: bool,
) {
  let mut claim_bytes: DynamicArray<Field, MAX_CLAIM_LEN> = DynamicArray::init();
  // copy then actual bytes of the claim value into the dynamic arrayg
  for i in 0..MAX_CLAIM_LEN {
    if claim[i] != NON_ASCII_CODE {
      claim_bytes.push(claim[i]);
    }
  }

  let mut encoded_claim = Encoder::encode(claim_bytes);

  if has_padding {
    encoded_claim.delete_front(4);
    encoded_claim.delete_back(4);
  }

  let jwt_slice = get_slice(jwt, start_index);
  let mut j = 0;

  for i in 0..MAX_ENCODED_SIZE as Field {
    if encoded_claim.get(i).has_value() {
      if encoded_claim.get(i).unwrap() as u16 != get_padding_char() {
        let jwt_byte = jwt_slice.get(j).unwrap();
        j += 1;

        assert(encoded_claim.get(i).unwrap() == jwt_byte);
      }
    }
  }
}
