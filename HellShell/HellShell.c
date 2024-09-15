#include <Windows.h>
#include <stdio.h>

#include "Common.h"

// array of supported output (supported input argv[2] encryption/obfuscation type)
CHAR* SupportedOutput[] = { "mac", "ipv4", "ipv6", "uuid", "aes", "rc4"};


// in case we need to make the shellcode multiple of something, we use this function and we make it multiple of *MultipleOf* parameter
// return the base address and the size of the new payload (appeneded payload)
BOOL AppendInputPayload(IN INT MultipleOf, IN PBYTE pPayload, IN DWORD dwPayloadSize, OUT PBYTE* ppAppendedPayload, OUT DWORD* pAppendedPayloadSize) {
	
	PBYTE	Append			= NULL;
	DWORD	AppendSize		= NULL;
	
	// calculating new size
	AppendSize = dwPayloadSize + MultipleOf - (dwPayloadSize % MultipleOf);

	// allocating new payload buffer
	Append = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AppendSize);
	if (Append == NULL)
		return FALSE;

	// filling all with nops
	memset(Append, 0x90, AppendSize);

	// copying the payload bytes over
	memcpy(Append, pPayload, dwPayloadSize);
	
	// returning
	*ppAppendedPayload = Append;
	*pAppendedPayloadSize = AppendSize;
	
	return TRUE;
}





// print help
INT PrintHelp(IN CHAR* _Argv0) {
	printf("\t\t\t ###########################################################\n");
	printf("\t\t\t # HellShell - Designed By Pentesterclubpvtltd @alex14324 | @Pentesterclub #\n");
	printf("\t\t\t ###########################################################\n\n");

	printf("[!] Usage: %s <Input Payload FileName> <Enc/Obf *Option*> \n", _Argv0);
	printf("[i] Options Can Be : \n");
	printf("\t1.>>> \"mac\"     ::: Output The Shellcode As A Array Of Mac Addresses  [FC-48-83-E4-F0-E8]\n");
	printf("\t2.>>> \"ipv4\"    ::: Output The Shellcode As A Array Of Ipv4 Addresses [252.72.131.228]\n");
	printf("\t3.>>> \"ipv6\"    ::: Output The Shellcode As A Array Of Ipv6 Addresses [FC48:83E4:F0E8:C000:0000:4151:4150:5251]\n");
	printf("\t4.>>> \"uuid\"    ::: Output The Shellcode As A Array Of UUid Strings   [FC4883E4-F0E8-C000-0000-415141505251]\n");
	printf("\t5.>>> \"aes\"     ::: Output The Shellcode As A Array Of Aes Encrypted Shellcode With Random Key And Iv\n");
	printf("\t6.>>> \"rc4\"     ::: Output The Shellcode As A Array Of Rc4 Encrypted Shellcode With Random Key\n");

	printf("\n\n[i] ");
	system("PAUSE");
	return -1;

}



int main(int argc, char* argv[]) {

	

	// data to help us in dealing with user's input
	DWORD	dwType				= NULL;
	BOOL	bSupported			= FALSE;
	
	// variables used for holding data on the read payload 
	PBYTE	pPayloadInput		= NULL;
	DWORD	dwPayloadSize		= NULL;

	// just in case we needed to append out input payload:
	PBYTE	pAppendedPayload	= NULL;
	DWORD	dwAppendedSize		= NULL;

	// variables used for holding data on the encrypted payload (aes/rc4)
	PVOID	pCipherText			= NULL;
	DWORD	dwCipherSize		= NULL;

	// checking input
	if (argc != 3) {
		return PrintHelp(argv[0]);
	}

	// verifying input
	for (size_t i = 0; i < 6; i++){
		if (strcmp(argv[2], SupportedOutput[i]) == 0) {
			bSupported = TRUE;
			break;
		}
	}
	if (!bSupported){
		printf("<<<!>>> \"%s\" Is not Valid Input <<<!>>>\n", argv[2]);
		return PrintHelp(argv[0]);
	}

	// reading input payload
	if (!ReadPayloadFile(argv[1], &dwPayloadSize, &pPayloadInput)) {
		return -1;
	}

	// intialize the possible append variables, since later we will deal with these only to print (*GenerateXXXOutput* functions)
	pAppendedPayload	= pPayloadInput;
	dwAppendedSize		= dwPayloadSize;

	// if mac fuscation is selected
	if (strcmp(argv[2], "mac") == 0){
		// if payload isnt multiple of 6 we padd it
		if (dwPayloadSize % 6 != 0){
			if (!AppendInputPayload(6, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of mac addresses from new appended shellcode 
		if (!GenerateMacOutput(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}


		dwType = MACFUSCATION;
		goto _EndOfFunction;
	}

	if (strcmp(argv[2], "ipv4") == 0){
		// if payload isnt multiple of 4 we padd it
		if (dwPayloadSize % 4 != 0) {
			if (!AppendInputPayload(4, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of ipv4 addresses from new appended shellcode 
		if (!GenerateIpv4Output(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}

		dwType = IPV4FUSCATION;
		goto _EndOfFunction;
	}

	if (strcmp(argv[2], "ipv6") == 0) {
		// if payload isnt multiple of 16 we padd it
		if (dwPayloadSize % 16 != 0) {
			if (!AppendInputPayload(16, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}

		// generate array of ipv6 addresses from new appended shellcode 
		if (!GenerateIpv6Output(pAppendedPayload, dwAppendedSize)) {
			return -1;
		}

		dwType = IPV6FUSCATION;
		goto _EndOfFunction;
	}

	if (strcmp(argv[2], "uuid") == 0) {
		// if payload isnt multiple of 16 we padd it
		if (dwPayloadSize % 16 != 0) {
			if (!AppendInputPayload(16, pPayloadInput, dwPayloadSize, &pAppendedPayload, &dwAppendedSize)) {
				return -1;
			}
		}
		// generate array of uuid addresses from new appended shellcode 
		if (!GenerateUuidOutput(pAppendedPayload, dwAppendedSize)){
			return -1;
		}

		dwType = UUIDFUSCATION;
		goto _EndOfFunction;
	}

	if (strcmp(argv[2], "aes") == 0) {

		CHAR	KEY			[AESKEYSIZE], KEY2[AESKEYSIZE];
		CHAR	IV			[AESIVSIZE], IV2[AESIVSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, AESKEYSIZE);
		srand(time(NULL) ^ KEY[0]);
		GenerateRandomBytes(IV, AESIVSIZE);

		//saving the key and iv in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, AESKEYSIZE);
		memcpy(IV2, IV, AESIVSIZE);

		if (!SimpleEncryption(pPayloadInput, dwPayloadSize, KEY, IV, &pCipherText, &dwCipherSize)) {
			return -1;
		}

		PrintDecodeFunctionality(AESENCRYPTION);
		PrintHexData("AesCipherText", pCipherText, dwCipherSize);
		PrintHexData("AesKey", KEY2, AESKEYSIZE);
		PrintHexData("AesIv", IV2, AESIVSIZE);

		goto _EndOfFunction;
	}

	if (strcmp(argv[2], "rc4") == 0) {

		CHAR	KEY			[RC4KEYSIZE], KEY2[RC4KEYSIZE];

		srand(time(NULL));
		GenerateRandomBytes(KEY, RC4KEYSIZE);

		//saving the key in case it got modified by the encryption algorithm
		memcpy(KEY2, KEY, RC4KEYSIZE);

		if (!Rc4EncryptionViSystemFunc032(KEY, pPayloadInput, RC4KEYSIZE, dwPayloadSize)){
			return -1;
		}

		PrintDecodeFunctionality(RC4ENCRYPTION);
		PrintHexData("Rc4CipherText", pPayloadInput, dwPayloadSize);
		PrintHexData("Rc4Key", KEY2, RC4KEYSIZE);
		
		goto _EndOfFunction;
	}


	// printing some gap
	printf("\n\n");


_EndOfFunction:
	if (pPayloadInput != NULL)
		HeapFree(GetProcessHeap(), 0, pPayloadInput); 
	if (pCipherText != NULL)
		HeapFree(GetProcessHeap(), 0, pCipherText); 
	if (pAppendedPayload != NULL && pAppendedPayload != pPayloadInput)
		HeapFree(GetProcessHeap(), 0, pAppendedPayload); 
	if (dwType != NULL)
		PrintDecodeFunctionality(dwType);
	return 0;
}








