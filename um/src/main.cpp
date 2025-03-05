#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>


static DWORD get_process_id(const wchar_t* process_name) {
	DWORD process_id = 0;
	HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snap_shot == INVALID_HANDLE_VALUE)
	{
		return process_id;
	}
	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(decltype(entry));

	if (Process32FirstW(snap_shot, &entry) == TRUE)
	{
		if (_wcsicmp(process_name, entry.szExeFile) == 0)
		{
			process_id = entry.th32ProcessID;
		}
		else {

			while (Process32NextW(snap_shot, &entry) == TRUE)
			{
				if (_wcsicmp(process_name, entry.szExeFile) == 0)
				{
					process_id = entry.th32ProcessID;
					break;
				}
			}


		}
	}


	CloseHandle(snap_shot);
	return process_id;

}
static std::uintptr_t get_module_base(const DWORD pid, const wchar_t* module_name) {
	std::uintptr_t module_base = 0;

	HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

	if (snap_shot == INVALID_HANDLE_VALUE)
	{
		printf("failed to find module base.\n");
		return module_base;
	}
	printf("finding module base.\n");

	MODULEENTRY32W entry = {};
	entry.dwSize = sizeof(decltype(entry));

	if (Module32FirstW(snap_shot, &entry) == TRUE)
	{
		if (_wcsicmp(module_name, entry.szModule) == 0)

		{
			module_base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
		}
		else {

			while (Module32NextW(snap_shot, &entry) == TRUE)
			{
				if (wcsstr(module_name, entry.szModule) != nullptr)
				{
					module_base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
					break;
				}
			}


		}
	}



	CloseHandle(snap_shot);
	return module_base;
}




namespace  driver {
	namespace codes {
		constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}
	struct  Request {
		HANDLE procees_id;

		PVOID target;
		PVOID buffer;

		SIZE_T size;
		SIZE_T return_size;

	};



	bool attach_to_process(HANDLE driver_handle, const DWORD pid) {
		Request r;
		r.procees_id = reinterpret_cast<HANDLE>(pid);
		return DeviceIoControl(driver_handle, codes::attach,
			&r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
	}

	template <class T>
	T read_memory(HANDLE driver_handle, const std::uintptr_t addr) {
		T temp = {};
		Request r;
		r.target = reinterpret_cast<PVOID>(addr);
		r.buffer = &temp;
		r.size = sizeof(T);

		DeviceIoControl(driver_handle, codes::read,
			&r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
		return temp;

	}

	template <class T>
	void write_memory(HANDLE driver_handle, const std::uintptr_t addr, const T& value)
	{
		Request r;
		r.target = reinterpret_cast<PVOID>(addr);
		r.buffer = (PVOID)&value;
		r.size = sizeof(T);

		DeviceIoControl(driver_handle, codes::write,
			&r, sizeof(r), &r, sizeof(r), nullptr, nullptr);

	}


}







void ReadIAT(HANDLE driver, DWORD pid, uintptr_t baseAddress) {
	printf("Starting IAT reading...\n");

	// Print base address of the process
	printf("Base Address of target process: 0x%lx\n", (unsigned long)baseAddress);

	// Read the DOS header
	IMAGE_DOS_HEADER dosHeader = driver::read_memory<IMAGE_DOS_HEADER>(driver, baseAddress);
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS Header.\n");
		return;
	}

	// Read NT headers
	IMAGE_NT_HEADERS ntHeaders = driver::read_memory<IMAGE_NT_HEADERS>(driver, baseAddress + dosHeader.e_lfanew);
	if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
		printf("Invalid NT Headers Signature.\n");
		return;
	}

	printf("NT Header Signature: 0x%lx\n", (unsigned long)ntHeaders.Signature);

	// Get the Import Table's virtual address
	DWORD importDescriptorVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (importDescriptorVA == 0) {
		printf("No Import Table found.\n");
		return;
	}

	printf("Import Table Virtual Address: 0x%X\n", importDescriptorVA);

	// Convert Virtual Address to actual memory address
	DWORD currentDescriptorAddr = baseAddress + importDescriptorVA;

	// Debug: Read first 16 bytes of Import Table
	printf("First 16 bytes of Import Table:\n");
	for (int i = 0; i < 16; i++) {
		DWORD value = driver::read_memory<DWORD>(driver, currentDescriptorAddr + i * sizeof(DWORD));
		printf("0x%X: 0x%X\n", currentDescriptorAddr + i * sizeof(DWORD), value);
	}

	int descriptorCount = 0;
	while (true) {
		// Read the Import Descriptor
		IMAGE_IMPORT_DESCRIPTOR importDescriptor = driver::read_memory<IMAGE_IMPORT_DESCRIPTOR>(driver, currentDescriptorAddr);

		// Debug: Print descriptor details
		printf("Descriptor Address: 0x%X\n", currentDescriptorAddr);
		printf("  Name RVA: 0x%X\n", importDescriptor.Name);
		printf("  FirstThunk RVA: 0x%X\n", importDescriptor.FirstThunk);

		// If Name is 0, we're at the end of the table
		if (importDescriptor.Name == 0) {
			printf("End of Import Table.\n");
			break;
		}

		descriptorCount++;

		// Read DLL name
		DWORD dllNameAddr = baseAddress + importDescriptor.Name;
		char dllName[256] = { 0 };
		for (int i = 0; i < 255; i++) {
			dllName[i] = driver::read_memory<char>(driver, dllNameAddr + i);
			if (dllName[i] == '\0') break;
		}

		printf("Imported DLL: %s\n", dllName);

		// Read IAT Address
		DWORD iatVA = importDescriptor.FirstThunk;
		if (iatVA == 0) {
			printf("No IAT for this import.\n");
			currentDescriptorAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
			continue;
		}

		DWORD iatAddr = baseAddress + iatVA;
		printf("IAT Address: 0x%X\n", iatAddr);

		// Read Function Pointers
		int functionCount = 0;
		DWORD functionAddress;
		while (true) {
			functionAddress = driver::read_memory<DWORD>(driver, iatAddr + functionCount * sizeof(DWORD));
			if (functionAddress == 0) break; // End of functions

			printf("Function %d Address: 0x%X\n", functionCount + 1, functionAddress);
			functionCount++;
		}

		// Move to the next import descriptor
		currentDescriptorAddr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	if (descriptorCount == 0) {
		printf("No valid import descriptors found.\n");
	}
}



	//printf("IMAGE_DOS_HEADER:\n");
	//printf("  e_magic: 0x%X (DOS Signature)\n", dosHeader.e_magic);
	//printf("  e_lfanew: 0x%X (Offset to NT Headers)\n", dosHeader.e_lfanew);
	//printf("  e_cblp: 0x%X\n", dosHeader.e_cblp);
	//printf("  e_cp: 0x%X\n", dosHeader.e_cp);
	//printf("  e_crlc: 0x%X\n", dosHeader.e_crlc);
	//printf("  e_cparhdr: 0x%X\n", dosHeader.e_cparhdr);
	//printf("  e_minalloc: 0x%X\n", dosHeader.e_minalloc);
	//printf("  e_maxalloc: 0x%X\n", dosHeader.e_maxalloc);
	//printf("  e_ss: 0x%X\n", dosHeader.e_ss);
	//printf("  e_sp: 0x%X\n", dosHeader.e_sp);
	//printf("  e_csum: 0x%X\n", dosHeader.e_csum);
	//printf("  e_ip: 0x%X\n", dosHeader.e_ip);
	//printf("  e_cs: 0x%X\n", dosHeader.e_cs);
	//printf("  e_lfarlc: 0x%X\n", dosHeader.e_lfarlc);
	//printf("  e_ovno: 0x%X\n", dosHeader.e_ovno);












//=======================================================================================
//=======================================================================================
//=======================================================================================
//=======================================================================================
//=======================================================================================


int main() {


	const wchar_t* process_name = L"notepad.exe";

	const DWORD pid = get_process_id(process_name);
	if (pid == 0)
	{
		std::cout << "Failed to find norepad \n";
		std::cin.get();
		return 1;
	}
	printf("process id: %d \n", pid);
	const HANDLE driver = CreateFile(L"\\\\.\\first_driver", GENERIC_READ, 0,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (driver == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed to create driver handle. \n";
		std::cin.get();
		return 1;

	}



	if (driver::attach_to_process(driver, pid) == true)
	{
		std::cout << "Attachment successful. \n";

	}	
	std::uintptr_t baseAddress = get_module_base(pid, process_name);








	printf("Base Address: 0x%X\n", baseAddress);

	ReadIAT(driver, pid, baseAddress);





	CloseHandle(driver);
	std::cin.get();
	return 0;
}


