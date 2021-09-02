/* SETUP EVIROMENT OPTION=========================================================================================================================================*/

//compile option: edit 2 flag
//#pragma strict_gs_check(off)				//GS fag(Securyty check)
//MT or MTD flag:  Poject Properties -> C/C++ -> Code Generation -> Runtime Library -> MT(For Release)/ MTD(For Debug)

//linker option: edit 3 flag
//#pragma comment(linker, "/FIXED")			//https://docs.microsoft.com/en-us/cpp/build/reference/fixed-fixed-base-address?view=vs-2019
//#pragma comment(linker, "/DYNAMICBASE:NO")	//https://docs.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization?view=vs-2019
//#pragma comment(linker, "/NXCOMPAT:NO")		//https://docs.microsoft.com/en-us/cpp/build/reference/nxcompat-compatible-with-data-execution-prevention?view=vs-2019
/*================================================================================================================================================================= */




#include <stdio.h>
#include <windows.h>

/* --------Global Data: belong to .data or .rdata or.bss section---------------*/
unsigned char var[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 }; // dec: 123456789
/*
	VA  - Vitural Address	(Address of process): Each process have each VA  start with addr 0x00000000. Process load many file into VA
	RVA - Relative Vitural Address	(Relative Address of file)   : Each file    have each RVA start with addr 0x00000000.
	https://stackoverflow.com/questions/2170843/va-virtual-address-rva-relative-virtual-address
*/
#define	BASE_ADDRESS			0x00400000 // File VA (Base address of file)
#define PACK_RVA				0x0001D000 // RVA of .pack
#define PACK_VA					BASE_ADDRESS + PACK_RVA // VA of .pack
#define PACK_FILE_ADDRESS		0x00001E00 // Point to .pack data (in file - not in ram )
//#define PACK_SIZE				0x00000016// Size of .pack
#define PACK_SIZE				0x00000400// Size of .pack
#define PACK_DISPLAY_SIZE		0x00000016 // Size of .pack will display for testing.
/*----------------------------------------------------------------------*/

/* .packVirutalAddress section - CREATE ----------------------------------------------*/
#pragma section(".pack",execute,read, write)
#pragma comment(linker, "/SECTION:.pack,ERW")
/* .packVirutalAddress section - BEGIN */
#pragma code_seg(".pack") /*Code after here belong to .packVirutalAddress section */
void pack_displayPackSectionData(n) { /*Display the first n bytes of .pack*/
	int* packVirutalAddress;
	packVirutalAddress = PACK_VA;
	int readed_byte = 0;
	while (readed_byte < n) {
		int dataAddress = PACK_FILE_ADDRESS + readed_byte;
		printf("%08X\t", dataAddress);
		for (int j = 0; j < 4; j++) {							//Display 4 raw ( 4x4=16byte) each line
			printf("%08X ", packVirutalAddress[readed_byte / 4]); // Because each times read int (4 byte)
			readed_byte += 4;									// Because each times read int (4 byte)
		}
		printf("\n");
	}
}
void main() {
	printf("\n\n=====Now in main\n");
	printf("=====.packVirutalAddress AFTER DECRYPT!\n");
	pack_displayPackSectionData(PACK_DISPLAY_SIZE);/*Display the first n bytes of .pack*/
	return;
}
/* .packVirutalAddress section - END ------------------------------------------------*/




/* .sub section -CAREATE ----------------------------------------------*/
#pragma section(".stub",execute, read)
/* .stub section -BEGIN */
#pragma code_seg(".stub") /* Code after here belong to .stub section*/
void stub_decryptCodeSection() {
	int* ptr;
	long int i;
	long int nbytes;
	ptr = PACK_VA;
	nbytes = PACK_SIZE;
	printf("Start decrypt\n");
	printf("%-8s\t%-8s\tDecrypted Data\n", "VA", "VRA");
	for (i = 0; i < nbytes; i++) {
		printf("%08X\t%08X\t", PACK_VA + i, i);
		for (int j = 0; j < 4; j++) {
			int tmp = ptr[i / 4];
			ptr[i / 4] = ~tmp;
			i += 4;
			printf("%08X ", ~tmp);
		};
		printf("\n");
		i -= 1;
	}
	/*
	while (i < nbytes) {
		for (int j = 0; j < 4; j++) {
			BYTE tmp = ptr[i];
			ptr[i] = ~tmp;
			i += 1;
			printf("%X ", ptr[i]);
		}

	}
	*/
	printf("\nENd Decrypt\n");
	return;
}
void stub_displayPackSectionData(n) {/*Display the first n bytes of .pack*/
	int* packVirutalAddress;        // pointer variable 
	packVirutalAddress = PACK_VA;       // store address of var in pointer variable
	int readed_byte = 0;
	while (readed_byte < n) {
		int dataAddress = PACK_FILE_ADDRESS + readed_byte;
		printf("%08X\t", dataAddress);
		for (int j = 0; j < 4; j++) {							//Display 4 raw ( 4x4=16byte) each line
			printf("%08X ", packVirutalAddress[readed_byte / 4]); // Because each times read int (4 byte)
			readed_byte += 4;									// Because each times read int (4 byte)
		}
		printf("\n");
	}
}
int StubEntry() {
	printf("Started In Stub()\n");
	printf("=====.packVirutalAddress BEFORE DECRYPT\n");
	stub_displayPackSectionData(PACK_DISPLAY_SIZE);/*Display the first n bytes of .pack*/
	stub_decryptCodeSection();
	main();
	return 0;
}
/*.stub section - END ------------------------------------------------*/


/*Program Start at StubEntry()- not at main()*/
#pragma comment(lib, "msvcrtd.lib")//#pragma comment(lib, "NODEFAULTLIB:\"msvcrtd.lib\"")
#pragma comment(linker, "/INCLUDE:_mainCRTStartup")
#pragma comment(linker,"/entry:\"StubEntry\"")	

/*MERGE .text and .data to .pack
https://docs.microsoft.com/en-us/cpp/build/reference/merge-combine-sections?view=vs-2019
*/
//#pragma comment(linker, "/MERGE:.text=.pack")
#pragma comment(linker, "/MERGE:.data=.pack")

/**/
//#pragma init_seg(".stub")//https://docs.microsoft.com/en-us/cpp/preprocessor/init-seg?view=vs-2019




