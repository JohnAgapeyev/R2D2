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
 * ];
 * garbage = [
 *      //I don't even know what this would be, it's just an example
 *      ".byte 0xCD 0xF9",
 * ];
 */
