# Rust shellcode suite

This is a suite for generating shellcode from a `no_std` context, outputting the result in a bin file. The suite comes with a shellcode injector, which will accept a pid for a process to inject into; you can either hard-code the shellcode, or have it read from a bin path.

The shellcode itself is currently a base to be moulded into a specific use case, with reading the PEB and export address table.

Project inspired directly by [b1tg](https://github.com/b1tg/rust-windows-shellcode) on GitHub (check them out); used my function (slightly modified) from my project here for reading the PEB, but implemented b1tg's function for finding the export function (I couldn't quite get mine to work without throwing memory access violations that proved arduous to debug properly as it only happened when injected into another process interestingly).

# POC

The POC for this opens calc.exe, but the shellcode could easily be modified to download remote data to execute.

# Legal disclaimer

This project, including all associated source code and documentation, is developed and shared solely for educational, research, and defensive purposes in the field of cybersecurity. It is intended to be used exclusively by cybersecurity professionals, researchers, and educators to enhance understanding, develop defensive strategies, and improve security postures.

Under no circumstances shall this project be used for criminal, unethical, or any other unauthorized activities. This is meant to serve as a resource for learning and should not be employed for offensive operations or actions that infringe upon any individual's or organization's rights or privacy.

The author of this project disclaims any responsibility for misuse or illegal application of the material provided herein. By accessing, studying, or using this project, you acknowledge and agree to use the information contained within strictly for lawful purposes and in a manner that is consistent with ethical guidelines and applicable laws and regulations.

USE AT YOUR OWN RISK. If you decide to use this software CONDUCT A THOROUGH INDEPENDENT CODE REVIEW to ensure it meets your standards. No unofficial third party dependencies are included to minimise attack surface of a supply chain risk. I cannot be held responsible for any problems that arise as a result of executing this, the burden is on the user of the software to validate its safety & integrity. All care has been taken to write safe code.

It is the user's responsibility to comply with all relevant local, state, national, and international laws and regulations related to cybersecurity and the use of such tools and information. If you are unsure about the legal implications of using or studying the material provided in this project, please consult with a legal professional before proceeding. Remember, responsible and ethical behavior is paramount in cybersecurity research and practice. The knowledge and tools shared in this project are provided in good faith to contribute positively to the cybersecurity community, and I trust they will be used with the utmost integrity.