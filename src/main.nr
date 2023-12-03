mod constants;
mod inclusion;

use dep::std;
use dep::collections::dynamic_array::DynamicArray;
use dep::base64::{
  constants::MAX_SIZE, encoder::Encoder, classic::get_padding_char,
};
use crate::{
  constants::{
    MAX_CLAIM_LEN, MAX_JWT_LEN, SIG_LEN, NON_ASCII_CODE, PADDING_CHARACTER,
  },
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
  iss_loc: u64, 
  jwt: [Field; MAX_JWT_LEN],
  sub: pub [Field; MAX_CLAIM_LEN],
  sub_loc: u64,
  // _sig: [Field; SIG_LEN],
) {
  let iss_has_padding = iss[1] == PADDING_CHARACTER;
  let sub_has_padding = sub[1] == PADDING_CHARACTER;
  
  prove_inclusion(iss, jwt, iss_loc, iss_has_padding);
  prove_inclusion(sub, jwt, sub_loc, sub_has_padding);
}

#[test]
fn test_main() {
  // add not ascci code
  let mut iss = [NON_ASCII_CODE; MAX_CLAIM_LEN];
  // not the @ which suggests that we use the offset-1 version of the encoded value
  let iss_str = "\"@iss\":\"https://securetoken.google.com/eutopic-staging-efa58\"".as_bytes();
  for i in 0..60 {
    iss[i] = iss_str[i] as Field;
  }

  // unlike iss we don't use any offset thus there are no precedding @ characters.
  let mut sub = [NON_ASCII_CODE; MAX_CLAIM_LEN];
  // TODO: replace this sensitive value
  let sub_str = "\"sub\":\"z8tANtNT3RTyiaNKEgAYuJE5RwV2\"".as_bytes();
  for i in 0..36 {
    sub[i] = sub_str[i] as Field;
  }

  let mut jwt: [Field; MAX_JWT_LEN] = [NON_ASCII_CODE; MAX_JWT_LEN];
  let jwt_str = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBiYmQyOTllODU2MmU3MmYyZThkN2YwMTliYTdiZjAxMWFlZjU1Y2EiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoicGF2bG9zIHBhcGEiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUxtNXd1MVBZWklDT1dfZFlNbW1fbHB0MG10VzBVUllRWjNDZXR6ZnN4Yzk9czk2LWMiLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vZXV0b3BpYy1zdGFnaW5nLWVmYTU4IiwiYXVkIjoiZXV0b3BpYy1zdGFnaW5nLWVmYTU4IiwiYXV0aF90aW1lIjoxNzAxNjIxMjE4LCJ1c2VyX2lkIjoiejh0QU50TlQzUlR5aWFOS0VnQVl1SkU1UndWMiIsInN1YiI6Ino4dEFOdE5UM1JUeWlhTktFZ0FZdUpFNVJ3VjIiLCJpYXQiOjE3MDE2MjEyMTgsImV4cCI6MTcwMTYyNDgxOCwiZW1haWwiOiJwcDZnMTFAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZ29vZ2xlLmNvbSI6WyIxMTczNjM5MTkxNzM0Mzc1NzU4MzAiXSwiZW1haWwiOlsicHA2ZzExQGdtYWlsLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6Imdvb2dsZS5jb20ifX0.XOQDEI9oDcUPFG3aRuw9u4xYcVh4NKMwzX1Qu9W0pESJiyRruEgC5aOhIUbfZ0AR82h-6EtXQRfh2RYaMu06OF-r6YwkLy642RYXIy4QcinnlACmaVlImTaqpczMC8nvOXNY4vzGWiPJl33IDOiai09MARkRlXoihAKJjGdeM84YQ2omoip9oaiSwBMu55jnN_i9kol_QywjSZtPdsjx6V1jCqH72s2IqmSHgybgXhNEK8xufXXI9IKaAnrf9uDxAnh6OU77s3f5D85HS1Dv_GOWZPEgIf-URMj4j4FouxLfh_NaQ928kETEDzd2fwKMgpIwbbkEw_1XBYi_Nuwa9g".as_bytes();
  for i in 0..819 {
    jwt[i] = jwt_str[i] as Field;
  }

  main(iss, 267, jwt, sub, 471);
}
