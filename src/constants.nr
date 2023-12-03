global MAX_CLAIM_LEN: u64 = 100;
global MAX_JWT_LEN: u64 = 1000;
global SIG_LEN: u64 = 256;
global NON_ASCII_CODE: Field = 256;
// This is the @ padding character we add to a value before encoding. It determined the offset used duting b64 search
global PADDING_CHARACTER: Field = 64;
