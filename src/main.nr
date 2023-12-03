mod constants;
mod inclusion;


use dep::std;
use dep::collections::dynamic_array::DynamicArray;
use dep::base64::{
  constants::MAX_SIZE, encoder::Encoder, classic::get_padding_char,
};
use crate::{
  constants::{MAX_CLAIM_LEN, MAX_JWT_LEN, SIG_LEN},
  inclusion::prove_inclusion,
};

/// Accepts the following inputs
///
/// # Public
///
/// * `iss` - The provider id that issued the jwt. Note this should be in the form `"iss":"iss_value{}"`. We need
///           this because the circuit will search this ascii string within the base64 encoded jwt token.
///           It is important to note, that all ascii values we want to search for are provided have some
///           offset already applies to it. This is so we don't have to encode three different versions of the
///           same ascii string before we verify the inlusion of one those version within the jwt token. These versions are
///
///           1. `"iss":"iss_value{}"` - no characters preceded
///           2. `"_iss":"iss_value{}"` - one arbitraty character added i.e. 1 offset 
///           3. `"__iss":"iss_value{}"` - two arbitraty characters added i.e. 2 offset 
//           
///           We just have to prove that one of thre three possibled encoded versions of the ascii value is within the jwt token.
///           More about this https://mikeyveenstra.com/posts/base64-key-strings/.
/// * `iss_loc` - The location within the base64 encoded jwt token where the base64 encoded value of the `iss` is located.
///               The circuit must prove that if it base64 encodes the ascii iss value above then the result will be located
///               at `iss_loc`. That is it will start at that index. So the circuit has to prove that it contains all the bytes
///               of the encoded ascii iss value in the range [iss_loc, iss_loc + encoded_value_len]
///
/// # Private
/// 
/// * `jwt` - The jwt token (base64 encoded). It includes only the header and the payload. The signature is
///           passed as a separate param
/// * `sub` - The subject i.e. userId
/// * `sig` - This is the last part of the jwt token which is the signature of the header.payload
/// 
/// Note that we use a specific static length for each of the binary data below.  The values are pretty conservative
/// and should cover most use cases.
fn main(
  iss: pub [Field; MAX_CLAIM_LEN],
  iss_loc: Field, 
  jwt: [Field; MAX_JWT_LEN],
  sub: pub [Field; MAX_CLAIM_LEN],
  _sig: [Field; SIG_LEN],
) {
  prove_inclusion(iss, jwt);
}

// #[test]
// fn test_main() {
//   let mut value = [0; 4];
//   value[0] = 65;
//   value[1] = 66;
//   value[2] = 67;
//   value[3] = 68;
  
//   let expected: [Field] = [
//     81, 85, 74, 68,
//     82, 65, get_padding_char() as Field, get_padding_char() as Field,
//   ];

//   let result = main(value);

//   for i in 0..8 {
//     assert(result[i] == expected[i]);
//   }
// }
