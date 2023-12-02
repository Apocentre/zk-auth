use dep::std;
use dep::collections::dynamic_array::DynamicArray;
use dep::base64::{
  constants::MAX_SIZE, encoder::Encoder, classic::get_padding_char,
};

fn main(value: [Field; 4]) -> pub [Field; MAX_SIZE] {
  let mut arr = DynamicArray::init();
  for i in 0..4 {
    arr.push(value[i]);
  }

  let result = Encoder::encode(arr);
  let mut out: [Field; MAX_SIZE] = [0; MAX_SIZE];

  for i in 0..MAX_SIZE {
    let val = result.get(i as Field);

    if val.has_value() {
      out[i] = val.unwrap();
    }
  }

  out
}

#[test]
fn test_main() {
  let mut value = [0; 4];
  value[0] = 65;
  value[1] = 66;
  value[2] = 67;
  value[3] = 68;
  
  let expected: [Field] = [
    81, 85, 74, 68,
    82, 65, get_padding_char() as Field, get_padding_char() as Field,
  ];

  let result = main(value);

  for i in 0..8 {
    assert(result[i] == expected[i]);
  }
}
