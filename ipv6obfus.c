#include <Windows.h>
#include <stdio.h>

// disable error 4996 caused by sprintf()

#pragma warning (disable:4996)





// Take a buffer and copy it to another buffer that is a multiple of 16 in size
BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {

	PBYTE PaddedBuffer = NULL;
	SIZE_T PaddedSize = NULL;

	// Calc the nearest number that is a multiple of 16 and save it to PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);

	// Allocate a buffer to PaddedSize
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer) {
		printf("[-] Failed to Allocate Buffer, Error: 0x%ld", GetLastError());
		return FALSE;
	}

	// Clean the allocated buffer
	ZeroMemory(PaddedBuffer, PaddedSize);

	// Copying old buffer to a new padded buffer
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);

	// Saving the results
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize = PaddedSize;

	return TRUE;

}


// Function will take in 16 raw bytes and returns them in string IPv6 address format

char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	// Each segment or quartet of IPv6 is 32 bits
	char Output0[32], Output1[32], Output2[32], Output3[32];

	// There are 4 segments(quartets) in an IPv6 address
	// 8 quartets --> each quartet is 16 bits --> 8*16 = 128

	char result[128];

	// Generate output0 using first 4 bytes
	sprintf(Output0, "%0.2X%0.2X:%0.2X%0.2X", a, b, c, d);

	// Output1 using second 4 bytes
	sprintf(Output1, "%0.2X%0.2X:%0.2X%0.2X", e, f, g, h);

	//Output2 using third 4 bytes
	sprintf(Output2, "%0.2X%0.2X:%0.2X%0.2X", i, j, k, l);

	//Output3 using fourth 4 bytes
	sprintf(Output2, "%0.2X%0.2X:%0.2X%0.2X", m, n, o, p);

	sprintf(result, "%s:%s:%s:%s", Output0, Output1, Output2, Output3);

	return (char*)result;
}

// Generate the IPv6 output representation of the shellcode

// This function will require a pointer or base address of the shellcode and the buffer size in which the shellcode is stored in

BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
		
	// If the shellcode buffer is null or the shellcode size is not a muliple of 16, we will exit
	if (pShellcode == NULL || ShellcodeSize == NULL) {
		return FALSE;
	}

	printf("char* Ipv6Array [%d] = { \n\t", (int)(ShellcodeSize / 16));


	// Read one Shellcode byte at a time, when we have read a total of 16 bytes, the IPv6 address will be generated
	// 'c' is used to store the number of bytes already read, by default it start at 16
	int c = 16, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {
		
		// This condition tracks the number of bytes read
		// If c is equal to 16, it will enter the loop and generate the IPv6 address
		 
		if (c == 16) {
			counter++;
			// Generating the IPv6 Address from the read 16 bytes
			// Begin generating from i up until i+15

			IP = GenerateIpv6(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3], pShellcode[i + 4], pShellcode[i+5], pShellcode[i+6], pShellcode[i+7],
					pShellcode[i+8], pShellcode[i+9], pShellcode[i+10], pShellcode[i+11], pShellcode[i+12], pShellcode[i+13], pShellcode[i+14], pShellcode[i+15]);

			// Print the last IPv6 address
			if (i == ShellcodeSize - 16) {
				printf("\"%s\"", IP);
			}
			else {
				printf("\"%s\", ", IP);
			}

			// Reset 'c' variable to start reading next 16 bytes byte-by-byte
			c = 1; 

			// Beautify console output
			if (counter % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}

	printf("\n} \n\n");
	return TRUE;
}

unsigned char rawData[] = {
	0xDD, 0xF2, 0x15, 0x81, 0x67, 0xD2,
	0xAA, 0x59, 0xB0, 0xA0, 0x5F, 0xE8,
	0xBD, 0xB4, 0xF8, 0x3A, 0x19, 0xA6,
	0xA3, 0xFE, 0xB7, 0x43, 0x23, 0xED
};


int main(void) {

	PBYTE PaddedBuffer = NULL;
	SIZE_T PaddedBufferSize = NULL;

	if (sizeof(rawData) % 16 != 0) {
		PaddBuffer(rawData, sizeof(rawData), &PaddedBuffer, &PaddedBufferSize);
		GenerateIpv6Output(PaddedBuffer, PaddedBufferSize);
		
	}
	else {
		GenerateIpv6Output(rawData, sizeof(rawData));
	}

	if (PaddedBuffer != NULL) {
		HeapFree(GetProcessHeap(), 0, PaddedBuffer);
	}

	printf("[*] Press <Enter> to Quit...");
	getchar();

	return 0;
}