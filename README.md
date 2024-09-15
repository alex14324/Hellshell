HellShell

Welcome to HellShell, a powerful tool designed by the Pentesterclub team to assist with static evasion techniques for payloads. HellShell simplifies the process of encrypting and obfuscating shellcode using various methods, including XOR, RC4, AES encryption, and multiple obfuscation formats such as IPv4, IPv6, MAC addresses, and UUIDs.

Features
Obfuscation Support:

MAC Addresses: Converts shellcode into an array of MAC addresses.
IPv4 Addresses: Converts shellcode into an array of IPv4 addresses.
IPv6 Addresses: Converts shellcode into an array of IPv6 addresses.
UUID Strings: Converts shellcode into an array of UUID strings.
Encryption Support:

XOR: Apply XOR encryption to shellcode.
RC4: Apply RC4 encryption to shellcode with a randomly generated key.
AES: Apply AES encryption to shellcode with a randomly generated key and IV.
Padding: Supports payload padding for encryption methods to ensure proper alignment and size.

Decryption Functionality: Provides the necessary function to decrypt shellcode encrypted with the selected method.

Random Keys: Generates random encryption keys and IVs on every run for enhanced security.

Usage
To use HellShell, download the source code from this repository and compile it manually. Ensure you set the build option to Release for optimized performance.

Command Line Interface

HellShell.exe <Input Payload FileName> <Enc/Obf *Option*>


Options:

mac - Outputs the shellcode as an array of MAC addresses (e.g., FC-48-83-E4-F0-E8).

ipv4 - Outputs the shellcode as an array of IPv4 addresses (e.g., 252.72.131.228).

ipv6 - Outputs the shellcode as an array of IPv6 addresses (e.g., FC48:83E4:F0E8:C000:0000:4151:4150:5251).

uuid - Outputs the shellcode as an array of UUID strings (e.g., FC4883E4-F0E8-C000-0000-415141505251).

aes - Outputs the shellcode as AES-encrypted data with a randomly generated key and IV.

rc4 - Outputs the shellcode as RC4-encrypted data with a randomly generated key.

Examples
Generate AES-encrypted payload and print to console:
HellShell.exe calc.bin aes

Generate AES-encrypted payload and output to AesPayload.c
HellShell.exe calc.bin aes > AesPayload.c

Generate IPv6-obfuscated payload and print to console:
HellShell.exe calc.bin ipv6

Demo
Below is an image showcasing HellShell in action, demonstrating the encryption of a payload using the RC4 algorithm and outputting the result to a file.

Contact
For questions or support, please contact the Pentesterclub team:

Pentesterclubpvtltd: @Pentesterclub | @alex14324
Thank you for using HellShell. Happy Hacking!
