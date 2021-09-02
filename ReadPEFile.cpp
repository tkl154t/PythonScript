#include <Windows.h>
#include <winnt.h> // Define for PE file
#include <stdlib.h>
#include <stdio.h>

typedef struct _ADDRESS_INFO {
	DWORD moduleBase;
	DWORD moduleCodeOffset;
	DWORD fileCodeOffset;
	DWORD fileCodeSize;
}ADDRESS_INFO, * PADDRESS_INFO;

BOOL getHMODULE(
	char* fileName,
	HANDLE* hFile,
	HANDLE* hFileMapping,
	LPVOID* baseAddress
	) {
	printf("[GetHMODULE]: Opening %s\n", fileName);
	(*hFile) = CreateFileA(
		fileName,
		GENERIC_READ,
		FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
		);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[GetHMODULE]: CreateFile() failed\n");
		return(FALSE);
	}

	printf("[GetHMODULE]: Opening an unamed file mapping object\n");
	(*hFileMapping) = CreateFileMapping
	(
		*hFile,
		NULL,
		PAGE_READONLY,
		0,
		0,
		NULL
		);
	if ((*hFileMapping) == NULL) {
		CloseHandle(hFile);
		printf("[GetHMODULE]: CreateFileMapping() failed\n");
		return(FALSE);
	}

	printf("[GetHMODULE]: Mapping a view of the file\n");
	(*baseAddress) = MapViewOfFile(
		*hFileMapping,
		FILE_MAP_READ,
		0,
		0,
		0
		);
	if ((*baseAddress) == NULL) {
		CloseHandle(*hFileMapping);
		CloseHandle(*hFile);
		printf("GetHMODULE: Couldn't map view of file\n");
		return(FALSE);
	}
	return(TRUE);
}

int main() {
	char fileName[] = "E:\\Tool\\PortableTool\\ProcessMonitor\\Procmon.exe";
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID fileBaseAddress;
	//retVal = getHMODULE(fileName, &hFile, &hFileMapping, &fileBaseAddress);

	printf("[GetHMODULE]: Opening %s\n", fileName);
	hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[GetHMODULE]: CreateFile() failed\n");
	}

	printf("[GetHMODULE]: Opening an unamed file mapping object\n");
	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL) {
		CloseHandle(hFile);
		printf("[GetHMODULE]: CreateFileMapping() failed\n");
	}

	printf("[GetHMODULE]: Mapping a view of the file\n");
	fileBaseAddress = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if ((fileBaseAddress) == NULL) {
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		printf("GetHMODULE: Couldn't map view of file\n");
	}
	else {
		printf("File loaded into address: 0x%08X\n", fileBaseAddress);
	}

	//GetCodeLoc(fileBaseAddress, &addrInfo);

	//IMAGE_OPTIONAL_HEADER32 optionalHeader = (*peHeader).OptionalHeader;

	int VA = 0;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBaseAddress;
	printf("IMAGE_DOS_HEADER:\n");
	printf("\t%08X\t%-35s:\\x%04X\n", VA, "Sinature", (*dosHeader).e_magic);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 2, "Bytes on last page of file", dosHeader->e_cblp);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 4, "Pages in file", dosHeader->e_cp);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 6, "Relocations", dosHeader->e_crlc);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 8, "Size of header in paragraphs", dosHeader->e_cparhdr);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 10, "Minimum extra paragraphs needed", dosHeader->e_minalloc);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 12, "Maximum extra paragraphs needed", dosHeader->e_maxalloc);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 14, "Initial (relative) SS value", dosHeader->e_ss);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 16, "Initial SP value", dosHeader->e_sp);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 18, "Checksum", dosHeader->e_csum);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 20, "Initial IP value", dosHeader->e_ip);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 22, "Initial (relative) CS value", dosHeader->e_cs);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 24, "File address of relocation table", dosHeader->e_lfarlc);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 26, "Overlay number", dosHeader->e_ovno);

	printf("\t%08X\t%-35s:\\x%04X\n", VA + 28, "Reserved words", dosHeader->e_res[0]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 30, "Reserved words", dosHeader->e_res[1]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 32, "Reserved words", dosHeader->e_res[2]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 34, "Reserved words", dosHeader->e_res[3]);

	printf("\t%08X\t%-35s:\\x%04X\n", VA + 36, "OEM identifier (for e_oeminfo)", dosHeader->e_oemid);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 38, "OEM information; e_oemid specific", dosHeader->e_oeminfo);

	printf("\t%08X\t%-35s:\\x%04X\n", VA + 40, "Reserved words", dosHeader->e_res2[0]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 42, "Reserved words", dosHeader->e_res2[1]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 44, "Reserved words", dosHeader->e_res2[2]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 46, "Reserved words", dosHeader->e_res2[3]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 48, "Reserved words", dosHeader->e_res2[4]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 50, "Reserved words", dosHeader->e_res2[5]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 52, "Reserved words", dosHeader->e_res2[6]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 54, "Reserved words", dosHeader->e_res2[7]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 56, "Reserved words", dosHeader->e_res2[8]);
	printf("\t%08X\t%-35s:\\x%04X\n", VA + 58, "Reserved words", dosHeader->e_res2[9]);

	printf("\t%08X\t%-35s:\\x%08X\n", VA + 60, "File address of new exe header", dosHeader->e_lfanew);

	/* END - IMAGE_DOS_HEADER*/

	/* MS-DOS Stub Program*/
	VA = 0x00000040; // STub start at 0x40
	VA = (int)fileBaseAddress + VA;
	int* stub_data = (int*)VA;
	printf("STUB DATA\n");
	for (int i = 0; i < (0xF0 - 0x40) / 4; i++) {
		for (int j = 0; j < 4; j++) {
			printf("%08X ", stub_data[i]);
			i++;
		}
		printf("\n");

	}
	printf("\n");
	/* END - MS-DOS Stub Program*/

	/*IMAGE_NT_HEADER*/

	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD)fileBaseAddress + (*dosHeader).e_lfanew);
	VA = dosHeader->e_lfanew;
	printf("IMAGE_NT_HEADER\n");
	printf("\t%08X\t%-35s:\\x%08X\n", VA, "Signature", ntHeader->Signature);
	IMAGE_FILE_HEADER image_file_header = ntHeader->FileHeader;
	printf("\tIMAGE_FILE_HEADER\n");
	printf("\t\t%08X\t%-35s:\\x%04X\n", VA + 4, "Machine", image_file_header.Machine);
	printf("\t\t%08X\t%-35s:\\x%04X\n", VA + 6, "Number of sections", image_file_header.NumberOfSections);
	printf("\t\t%08X\t%-35s:\\x%08X\n", VA + 8, "Time Date Stamp", image_file_header.TimeDateStamp);
	printf("\t\t%08X\t%-35s:\\x%08X\n", VA + 12, "Pointer To Symbol Table", image_file_header.PointerToSymbolTable);
	printf("\t\t%08X\t%-35s:\\x%08X\n", VA + 16, "Number Of Symbols", image_file_header.NumberOfSymbols);
	printf("\t\t%08X\t%-35s:\\x%04X\n", VA + 20, "Size Of Optional Header", image_file_header.SizeOfOptionalHeader);
	printf("\t\t%08X\t%-35s:\\x%04X\n", VA + 22, "Characteristics", image_file_header.Characteristics);
	IMAGE_OPTIONAL_HEADER image_optional_header = ntHeader->OptionalHeader;
	printf("\tIMAGE_OPTIONAL_HEADER\n");
	/* Tương tự ở trên*/
	/*END - IMAGE_NT_HEADER*/

	/*SECTION_HEADER*/
	printf("IMAGE_SECTION_HEADER\n");
	VA = 0x00000108 + ntHeader->FileHeader.SizeOfOptionalHeader;// Begin of IMAGE_OPTIONAL_HEADER + size of IMAGE_OPTIONAL_HEADER ->  address of first section
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
	int numOfSection = ntHeader->FileHeader.NumberOfSections;
	for (int i = 0; i < numOfSection; i++) {
		printf("\t%s: %s\n", "Section name", (*section).Name);
		printf("\t\t%08X\t%-15s: %08X\n", VA, "Virtual Address", (*section).VirtualAddress);
		printf("\t\tPointer To Raw Data:    %X\n\n", (*section).PointerToRawData);
		printf("\t\Size Of Raw Data:    %X\n\n", (*section).SizeOfRawData);
		section += 1;//next section
		VA += 40;	//Each section header 40byte
	}



	/*
	if (((*peHeader).Signature) != IMAGE_NT_SIGNATURE)
	{
		printf("[GetCodeLoc]: PE signature not matched\n");
	}
	printf("[GetCodeLoc]: PE signature=%X\n", (*peHeader).Signature);
	if ((optionalHeader.Magic) != 0x10B)
	{
		printf("[GetCodeLoc]: Optional header magic number does not match\n");
	}
	printf("[GetCodeLoc]: OPtional header magic nb=%X\n", optionalHeader.Magic);

	ADDRESS_INFO addrInfo;
	addrInfo.moduleBase = optionalHeader.ImageBase;

	printf("[GetCodeLoc]: # sections=%d\n", (*peHeader).FileHeader.NumberOfSections);

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(peHeader);
	DWORD nSections = (*peHeader).FileHeader.NumberOfSections;

	DWORD i;
	printf("[DumpSection]:-------------------\n\n");
	for (i = 0; i < nSections; i++)
	{
		printf("\tName:			%s\n", (*section).Name);
		printf("\tfile offset:  %X\n", (*section).PointerToRawData);
		printf("\tfile size:    %X\n\n", (*section).SizeOfRawData);
		if (strcmp((char*)(*section).Name, ".pack") == 0)
		{
			(addrInfo).fileCodeOffset = (*section).PointerToRawData;
			(addrInfo).fileCodeSize = (*section).SizeOfRawData;
		}
		section = section + 1;
	}
	*/
	return 0;
}