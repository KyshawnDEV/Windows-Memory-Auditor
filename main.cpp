#include <iostream>

int main()
{
    std::cout << "Hello World!\n";
    return 0;
}

//Structure to hold target findings
struct AuditMetrics {
    int critical = 0;
    int high = 0;
	int medium = 0;
	int low = 0;
};