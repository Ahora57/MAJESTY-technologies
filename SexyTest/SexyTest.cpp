#include <Windows.h>
#include <iostream>

 
int main()
{ 
	while (true)
	{
		if (GetAsyncKeyState(VK_SPACE))
		{
			std::cout << "Meh!\n";
			Sleep(500);
		}
		if (GetAsyncKeyState(VK_INSERT))
		{
			ExitProcess((UINT)"Sexy");
		}
	};
}

