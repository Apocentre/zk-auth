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
  sub: [Field; MAX_CLAIM_LEN],
  sub_loc: u64,
  // _sig: [Field; SIG_LEN],
) {
  // We want to know if the given search term is padded i.e. we added @ to get it in the right offset form.
  let iss_has_padding = iss[0] == PADDING_CHARACTER;
  let sub_has_padding = sub[0] == PADDING_CHARACTER;
  
  prove_inclusion(iss, jwt, iss_loc, iss_has_padding);
  prove_inclusion(sub, jwt, sub_loc, sub_has_padding);
}

#[test]
fn test_main() {
  // `@"iss":"https://securetoken.google.com/eutopic-staging-efa58"`
  let iss = [64,34,105,115,115,34,58,34,104,116,116,112,115,58,47,47,115,101,99,117,114,101,116,111,107,101,110,46,103,111,111,103,108,101,46,99,111,109,47,101,117,116,111,112,105,99,45,115,116,97,103,105,110,103,45,101,102,97,53,56,34,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256];
  // `"sub":"z8tANtNT3RTyiaNKEgAYuJE5RwV2"`
  let sub = [34,115,117,98,34,58,34,122,56,116,65,78,116,78,84,51,82,84,121,105,97,78,75,69,103,65,89,117,74,69,53,82,119,86,50,34,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256];
  // "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBiYmQyOTllODU2MmU3MmYyZThkN2YwMTliYTdiZjAxMWFlZjU1Y2EiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoicGF2bG9zIHBhcGEiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUxtNXd1MVBZWklDT1dfZFlNbW1fbHB0MG10VzBVUllRWjNDZXR6ZnN4Yzk9czk2LWMiLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vZXV0b3BpYy1zdGFnaW5nLWVmYTU4IiwiYXVkIjoiZXV0b3BpYy1zdGFnaW5nLWVmYTU4IiwiYXV0aF90aW1lIjoxNzAxNjIxMjE4LCJ1c2VyX2lkIjoiejh0QU50TlQzUlR5aWFOS0VnQVl1SkU1UndWMiIsInN1YiI6Ino4dEFOdE5UM1JUeWlhTktFZ0FZdUpFNVJ3VjIiLCJpYXQiOjE3MDE2MjEyMTgsImV4cCI6MTcwMTYyNDgxOCwiZW1haWwiOiJwcDZnMTFAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZ29vZ2xlLmNvbSI6WyIxMTczNjM5MTkxNzM0Mzc1NzU4MzAiXSwiZW1haWwiOlsicHA2ZzExQGdtYWlsLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6Imdvb2dsZS5jb20ifX0"
  let jwt = [101,121,74,104,98,71,99,105,79,105,74,83,85,122,73,49,78,105,73,115,73,109,116,112,90,67,73,54,73,106,66,105,89,109,81,121,79,84,108,108,79,68,85,50,77,109,85,51,77,109,89,121,90,84,104,107,78,50,89,119,77,84,108,105,89,84,100,105,90,106,65,120,77,87,70,108,90,106,85,49,89,50,69,105,76,67,74,48,101,88,65,105,79,105,74,75,86,49,81,105,102,81,46,101,121,74,117,89,87,49,108,73,106,111,105,99,71,70,50,98,71,57,122,73,72,66,104,99,71,69,105,76,67,74,119,97,87,78,48,100,88,74,108,73,106,111,105,97,72,82,48,99,72,77,54,76,121,57,115,97,68,77,117,90,50,57,118,90,50,120,108,100,88,78,108,99,109,78,118,98,110,82,108,98,110,81,117,89,50,57,116,76,50,69,118,81,85,120,116,78,88,100,49,77,86,66,90,87,107,108,68,84,49,100,102,90,70,108,78,98,87,49,102,98,72,66,48,77,71,49,48,86,122,66,86,85,108,108,82,87,106,78,68,90,88,82,54,90,110,78,52,89,122,107,57,99,122,107,50,76,87,77,105,76,67,74,112,99,51,77,105,79,105,74,111,100,72,82,119,99,122,111,118,76,51,78,108,89,51,86,121,90,88,82,118,97,50,86,117,76,109,100,118,98,50,100,115,90,83,53,106,98,50,48,118,90,88,86,48,98,51,66,112,89,121,49,122,100,71,70,110,97,87,53,110,76,87,86,109,89,84,85,52,73,105,119,105,89,88,86,107,73,106,111,105,90,88,86,48,98,51,66,112,89,121,49,122,100,71,70,110,97,87,53,110,76,87,86,109,89,84,85,52,73,105,119,105,89,88,86,48,97,70,57,48,97,87,49,108,73,106,111,120,78,122,65,120,78,106,73,120,77,106,69,52,76,67,74,49,99,50,86,121,88,50,108,107,73,106,111,105,101,106,104,48,81,85,53,48,84,108,81,122,85,108,82,53,97,87,70,79,83,48,86,110,81,86,108,49,83,107,85,49,85,110,100,87,77,105,73,115,73,110,78,49,89,105,73,54,73,110,111,52,100,69,70,79,100,69,53,85,77,49,74,85,101,87,108,104,84,107,116,70,90,48,70,90,100,85,112,70,78,86,74,51,86,106,73,105,76,67,74,112,89,88,81,105,79,106,69,51,77,68,69,50,77,106,69,121,77,84,103,115,73,109,86,52,99,67,73,54,77,84,99,119,77,84,89,121,78,68,103,120,79,67,119,105,90,87,49,104,97,87,119,105,79,105,74,119,99,68,90,110,77,84,70,65,90,50,49,104,97,87,119,117,89,50,57,116,73,105,119,105,90,87,49,104,97,87,120,102,100,109,86,121,97,87,90,112,90,87,81,105,79,110,82,121,100,87,85,115,73,109,90,112,99,109,86,105,89,88,78,108,73,106,112,55,73,109,108,107,90,87,53,48,97,88,82,112,90,88,77,105,79,110,115,105,90,50,57,118,90,50,120,108,76,109,78,118,98,83,73,54,87,121,73,120,77,84,99,122,78,106,77,53,77,84,107,120,78,122,77,48,77,122,99,49,78,122,85,52,77,122,65,105,88,83,119,105,90,87,49,104,97,87,119,105,79,108,115,105,99,72,65,50,90,122,69,120,81,71,100,116,89,87,108,115,76,109,78,118,98,83,74,100,102,83,119,105,99,50,108,110,98,108,57,112,98,108,57,119,99,109,57,50,97,87,82,108,99,105,73,54,73,109,100,118,98,50,100,115,90,83,53,106,98,50,48,105,102,88,48,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256];

  main(iss, 267, jwt, sub, 471);
}
