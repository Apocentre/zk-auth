use dep::std;
use dep::collections::dynamic_array::DynamicArray;
use dep::base64::{
  constants::MAX_SIZE, encoder::Encoder, classic::get_padding_char,
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
  iss: pub [Field; 100],
  jwt: [Field; 1000],
  sub: pub [Field; 64],
  _sig: [Field; 256],
) {

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
