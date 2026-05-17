#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <string>
#include <map>
#include <sstream>



std::string static GetCommand()
{
	std::string inputBuffer = "";
	std::getline(std::cin, inputBuffer);

	return inputBuffer;
}


void static send_output(std::string output)
{

	std::cout << output << std::endl;
}



std::string static ExecuteMicroShell(std::string input_command)
{


	return "";
}



int main()
{

	while(true)
	{
	
		std::cout << "YetAnotherShell>";

		std::string recieved_command = GetCommand();
		if(recieved_command.empty()) continue;
        
		
		if(recieved_command == "exit" || recieved_command == "quit") break;


		std::string output = ExecuteMicroShell(recieved_command);
		send_output(output);


	}

	return 0;
}


