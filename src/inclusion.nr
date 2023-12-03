use dep::collections::dynamic_array::DynamicArray;
use dep::base64::{
  encoder::Encoder, classic::get_padding_char,
};
use dep::poly_root::full_inclusive;
use crate::constants::{MAX_CLAIM_LEN, MAX_JWT_LEN, SIG_LEN, MAX_CLAIM_ENCODED_LEN};

fn get_slice(array: [Field; MAX_JWT_LEN], start: Field, end: Field) -> DynamicArray<Field, MAX_JWT_LEN> {
  let mut slice = DynamicArray::init();

  for i in 0..MAX_CLAIM_LEN {
    if full_inclusive::check(i as Field, start, end) {
      slice.push(array[i]);
    }
  }

  slice
}

pub fn prove_inclusion(
  claim: [Field; MAX_CLAIM_LEN],
  jwt: [Field; MAX_JWT_LEN],
  start_index: Field,
) {
  let mut claim = DynamicArray::from_array(claim);
  let encoded_claim = Encoder::encode(claim);
  let jwt_slice = get_slice(jwt, start_index, encoded_claim.len() as Field);
  
  for i in 0..MAX_CLAIM_ENCODED_LEN {
    if encoded_claim.get(i).has_value() {
      assert(encoded_claim.get(i).unwrap() == jwt_slice.get(i).unwrap());
    }
  }
}
