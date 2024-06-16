# Rust shellcode suite

This is a suite for generating shellcode from a `no_std` context, outputting the result in a bin file. The suite comes with a shellcode injector, which will accept a pid for a process to inject into; you can either hard-code the shellcode, or have it read from a bin path.

The shellcode itself is currently a base to be moulded into a specific use case, with reading the PEB and export address table.

Project inspired directly by [b1tg](https://github.com/b1tg/rust-windows-shellcode) on GitHub (check them out); used my function (slightly modified) from my project here for reading the PEB, but implemented b1tg's function for finding the export function (I couldn't quite get mine to work without throwing memory access violations that proved arduous to debug properly as it only happened when injected into another process interestingly).