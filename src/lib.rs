use proc_macro::TokenStream;
//use quote::quote;
use syn::{parse_macro_input, AttributeArgs, Item};

#[proc_macro_attribute]
pub fn obfuscate(args: TokenStream, input: TokenStream) -> TokenStream {
    let input2 = input.clone();
    let _ = parse_macro_input!(args as AttributeArgs);
    let input2 = parse_macro_input!(input2 as Item);

    eprintln!("INPUT: {:#?}", input2);

    input
}

