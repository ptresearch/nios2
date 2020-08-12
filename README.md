# NIOS2
 
## Definition
NIOS2 - this is an IDA Pro processor module for Altera Nios II Classic/Gen2 microprocessor architecture.

## Requirements
Developed for and tested on Python 2.7, IDA 6.9, and IDAPython 1.7.0.
Older versions should also work. IDA versions 7.0+ supported.

## Installation
Copy the file "nios2.py" to the procs subfolder of your IDA Pro installation.
For example in Windows:
location for IDA Pro 6.xx: "\Program Files (x86)\IDA 6.xx\procs\"
location for IDA Pro 7.xx: "\Program Files\IDA 7.xx\procs\"

## How to use
Launch IDA Pro, select the Altera Nios II Classic/Gen2 Processor processor type, and enjoy the reverse engineering goodness!

## NIOS II processor module: feature description

### Key features
Decodes instructions and operands, and displays them on screen. Generates comments for commands. Describes both general-purpose registers and control registers. Analyzes execution control instructions. Generates cross-references. Generates references from data also. Simplifies instructions: replaces certain combinations of commands and operands with pseudoinstructions (commands for which there are no separate opcodes). Monitors changes in stack pointer and supports stack variables. Handles situations when the stack pointer is involved in calculating offsets written to other registers by converting to the offsets for stack variables. Generates cross-references from code to separate fields of structures.

### 32-bit numbers and offsets
The NIOS II processor does not have a machine command for directly writing a 32-bit value to a register. At maximum, a 16-bit value can be written in a single command. Therefore, writing 32-bit numbers consists of two steps: the high half of the number is written to the high part of the register, while the low part is added, subtracted, or combined with the high part with the help of bitwise OR. If the 32-bit number is an offset, the low half can also be implemented in a command as a positive or negative offset relative to the base (the high half).
In the processor module, if a 32-bit number is an offset, an operand and cross-references are generated only from the low half, using the base taken from the high half. Setting a register to an offset, as well as reading or writing relative to the base, is handled. If a 32-bit number is not an offset, its value is simply output next to the command for writing the low half.

### Switch
All encountered schemes for organizing switch constructions are handled. The module recognizes switch variants when the scheme is interrupted by jumps, when instructions not part of the scheme are encountered between the main commands, and when the locations of main commands have been switched. A reverse execution path approach is used that takes into account possible jumps, with setting of internal variables that signal various states of the recognizer. In practice, the module successfully recognizes around 10 different switch organization variants.

### The custom instruction
The NIOS II architecture includes "custom", an interesting instruction that gives access to 256 user-set instructions and can access a set of 32 custom registers. The processor module implements support for the custom instruction and outputting command names for the FloatingPointHardware 2 (FPH2) component.

### Jumping by register value
Recognizes jumps by register value, with pre-writing of the offset to the register. Generates cross-references and outputs the name of the procedure or label next to the name of the jump command.

### Addressing via global pointer
The value of the global pointer in the gp register is determined in the background as the file is initially opened and navigated. The value of gp is saved in the idb database upon closing, and restored during loading. Variables that are addressed relative to gp in loading and save instructions are converted to offsets. Offset conversions are also performed when the gp register is involved in calculating offsets written to other registers. Thus the other register is set relative to the gp register for a certain region of data.

### IDA version 7 is supported.

## Author
Anton Dorfman ADorfman@ptsecurity.com (Positive Technologies)

## Contributor
[Blue DeviL // SCT](http://gitlab.com/bluedevil)

