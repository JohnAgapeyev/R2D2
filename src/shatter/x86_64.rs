/*
 * Current plan:
 * Vec of registers available to reference
 * Vec of instructions, containing template strings, with optional constraints
 * Constraint would be for things like x86 not allowing memory-to-memory mov instructions
 * Template would contain cutouts for things like immediate,register,memory, separated by size
 * A memory address should be 64 bit or with some complicated relative addressing
 * A register is one of a fixed set of names
 * An immediate size depends on the instruction
 *
 * We also need to have byte equivalents for partial instructions
 * May be as simple as ripping Isaac's list, or making my own
 * Just a set of bytes that counts as "an instruction", but without the required operand, creating
 * garbage once disassembled
 * Probably don't need to keep that in the same list as "good" code instructions
 *
 * Can probably utilize it as rust source code and format strings, they're powerful enough, and
 * I'd like to avoid string logic handling if possible
 *
 * Then it'd be just a matter of doing some lookups, string formatting, and deciding how much I
 * want to insert
 * Maybe I want to make the amount of garbage proportional to the chance of injection
 * Would keep the binary bloat fairly relative that way
 *
 * In the event I want to extend this to full sequences, it should just be a matter of having a
 * dynamic list of available template cutouts. Maybe this is done through string search, or maybe
 * it's a separate array with each instruction
 * Could also just make it another list similar to garbage instructions
 * But that's pretty low priority, I can likely get away with just doing single instruction
 * injections and repeating that.
 *
 * So for example, I'd expect something like:
 * registers = [
 *      "eax", 4
 *      "rax", 8
 *      ...
 * ];
 * instructions = [
 *      //r for register, m for memory, i for immediate
 *      { "adc {r}, {ri}", CONSTRAINT::NONE },
 *      { "mov {rm}, {rmi}", CONSTRAINT::NO_MEM_MEM },
 *
 *      { "adc {}, {}", vec![vec![ARGS::REGISTER], vec![ARGS::REGISTER, ARGS::IMMEDIATE]], vec![CONSTRAINT::NONE] },
 *
 *
 *
 *
 *
 *      { "op": "adc {}, {}", "args": [[ARGS::REGISTER], [ARGS::REGISTER, ARGS::IMMEDIATE]], "constraints": [CONSTRAINT::NONE] },
 * ];
 * garbage = [
 *      //I don't even know what this would be, it's just an example
 *      ".byte 0xCD 0xF9",
 * ];
 */

use quote::quote;
use rand;
use rand::distributions::Uniform;
use rand::prelude::*;
use rand::rngs::OsRng;
use syn::Block;

//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

const PARTIAL_PREFIXES: &str = include_str!("x86_64_prefixes.json");

pub fn generate_partial_instruction() -> Vec<u8> {
    //Format is instructions->encodings->bytes
    //Hence, 3 vecs, since multiple instructions have multiple encodings which may be multiple
    //bytes
    let underlying = serde_json::from_str::<Vec<Vec<Vec<u8>>>>(PARTIAL_PREFIXES).unwrap();

    let instruction = underlying.choose(&mut OsRng).unwrap();
    let encoding = instruction.choose(&mut OsRng).unwrap();
    encoding.to_owned()
}

pub fn generate_rabbit_hole() -> Block {
    //TODO: Extend the selection to have more than 1 kind of rabbit hole

    let between = Uniform::from(1..33);
    let rot: usize = between.sample(&mut OsRng);

    let data = format!(
        "\
        mov rax, rsp; \
        rcl rax, {rot}; \
        mov rsp, r14; \
        mov rbx, r9; \
        mov rdi, r8; \
        mov r8, rsi; \
        mov rsi, rbp; \
        rcr rsi, {rot}; \
        mov rbp, r10; \
        mov rcx, r11; \
        mov rdx, r12; \
        jmp [rax + 8*rbx + rsi]; \
        "
    );

    let body_content = quote! {
        {
            std::arch::asm!(
                #data,
                clobber_abi("C"),
            );
        }
    };
    syn::parse2::<Block>(body_content).unwrap()
}
