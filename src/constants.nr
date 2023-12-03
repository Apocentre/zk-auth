global MAX_CLAIM_LEN: u64 = 100;
global MAX_JWT_LEN: u64 = 1000;
global SIG_LEN: u64 = 256;
// base64 encoded value has len = 4/3 * ascii_string_len
global MAX_CLAIM_ENCODED_LEN: Field = 134;
