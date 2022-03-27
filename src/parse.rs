use proc_macro2::{Punct, Spacing};
use quote::*;
use syn::ext::*;
use syn::parse::*;
use syn::*;

//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

// The arguments expected by libcore's format_args macro, and as a
// result most other formatting and printing macros like println.
//
//     println!("{} is {number:.prec$}", "x", prec=5, number=0.01)
#[derive(Debug)]
pub struct FormatArgs {
    pub format_string: Expr,
    pub positional_args: Vec<Expr>,
    pub named_args: Vec<(Ident, Expr)>,
}

impl Parse for FormatArgs {
    fn parse(input: ParseStream) -> syn::parse::Result<Self> {
        let format_string: Expr;
        let mut positional_args = Vec::new();
        let mut named_args = Vec::new();

        format_string = input.parse()?;
        while !input.is_empty() {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }
            if input.peek(Ident::peek_any) && input.peek2(Token![=]) {
                while !input.is_empty() {
                    let name: Ident = input.call(Ident::parse_any)?;
                    input.parse::<Token![=]>()?;
                    let value: Expr = input.parse()?;
                    named_args.push((name, value));
                    if input.is_empty() {
                        break;
                    }
                    input.parse::<Token![,]>()?;
                }
                break;
            }
            positional_args.push(input.parse()?);
        }

        Ok(FormatArgs {
            format_string,
            positional_args,
            named_args,
        })
    }
}

impl ToTokens for FormatArgs {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let format = self.format_string.clone();
        let pos = self.positional_args.clone();

        tokens.append_all(quote! {
            #format, #(#pos),*
        });

        if !self.named_args.is_empty() {
            tokens.append(Punct::new(',', Spacing::Alone));
        }

        for (idx, (ident, expr)) in self.named_args.iter().enumerate() {
            tokens.append_all(quote! {#ident=#expr});

            if idx != self.named_args.len() - 1 {
                tokens.append(Punct::new(',', Spacing::Alone));
            }
        }
    }
}

#[derive(Debug)]
pub struct AssertArgs {
    pub condition: Expr,
    pub message: Option<FormatArgs>,
}

impl Parse for AssertArgs {
    fn parse(input: ParseStream) -> syn::parse::Result<Self> {
        let condition: Expr;
        let mut message: Option<FormatArgs> = None;

        condition = input.parse()?;
        let found_comma = input.parse::<Token![,]>();
        if found_comma.is_ok() {
            message = input.parse().ok();
        }

        Ok(AssertArgs {
            condition,
            message,
        })
    }
}

#[derive(Debug)]
pub struct AssertCmpArgs {
    pub first_condition: Expr,
    pub second_condition: Expr,
    pub message: Option<FormatArgs>,
}

impl Parse for AssertCmpArgs {
    fn parse(input: ParseStream) -> syn::parse::Result<Self> {
        let first_condition: Expr;
        let second_condition: Expr;
        let mut message: Option<FormatArgs> = None;

        first_condition = input.parse()?;
        input.parse::<Token![,]>()?;
        second_condition = input.parse()?;
        if input.parse::<Token![,]>().is_ok() {
            message = input.parse().ok();
        }

        Ok(AssertCmpArgs {
            first_condition,
            second_condition,
            message,
        })
    }
}
