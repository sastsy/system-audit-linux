#include <iostream>
#include <fstream>
#include <map>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include "pids.h"
#include <sys/reg.h>
#include <pwd.h>

using namespace std;

void check()
{
    if (errno == -1)
    {
        throw runtime_error(strerror(errno));
    }
}

std::ofstream logFile;

const int MAX_LOG_LINES = 100;

std::string getUsername(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    return (pw != nullptr) ? pw->pw_name : "UnknownUser";
}

std::string getCurrentDatetime()
{
    time_t now = time(0);
    tm* data = localtime(&now);

    std::ostringstream stream;
    stream << std::put_time(data, "%d.%m.%Y %H:%M:%S");
    return stream.str();
}

void log(unsigned long long code, int pid) {
    uid_t uid = getuid(); 
    std::string username = getUsername(uid);

    if (logFile.tellp() >= MAX_LOG_LINES)
    {
        logFile.close();
        std::ifstream inputFile("audit.log");
        std::ofstream tempFile("temp.log");

        string line;
        int count = 0;

        while (getline(inputFile, line) && count < MAX_LOG_LINES)
        {
            tempFile << line << endl;
            count++;
        }

        tempFile.close();
        inputFile.close();

        remove("audit.log");
        rename("temp.log", "audit.log");

        logFile.open("audit.log", std::ios_base::app);
    }

    logFile << '[' << pid << "] " << getCurrentDatetime() << " - User: " << username << ", " << pids[code] << '(' << code << ')' << std::endl;
}

void log(const char* data, int pid) {
    uid_t uid = getuid(); 
    std::string username = getUsername(uid);

    if (logFile.tellp() >= MAX_LOG_LINES)
    {
        logFile.close();
        std::ifstream inputFile("audit.log");
        std::ofstream tempFile("temp.log");

        string line;
        int count = 0;

        while (getline(inputFile, line) && count < MAX_LOG_LINES)
        {
            tempFile << line << endl;
            count++;
        }

        tempFile.close();
        inputFile.close();

        remove("audit.log");
        rename("temp.log", "audit.log");

        logFile.open("audit.log", std::ios_base::app);
    }

    logFile << '[' << pid << "] " << getCurrentDatetime() << " - User: " << username << ", " << data << std::endl;
}


int main(int argc, char** argv)
{
    if (argc != 2)
    {
        cout << "Usage: sudo ./Audit <pid>" << endl;
        cout << "       or" << endl;
        cout << "       sudo ./Audit `pidof <process name>`" << endl;
        return EXIT_FAILURE;
    }

    int pid = stoi(argv[1]);

    logFile.open("audit.log", std::ios_base::app);

    ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    check();
    log("Attached", pid);

    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
    check();
    log("Set sys call listener", pid);

    int status;
    waitpid(pid, &status, WUNTRACED);
    user_regs_struct regs;
    while (WIFSTOPPED(status))
    {
        ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
        check();
        waitpid(pid, &status, WUNTRACED);

        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        check();

        log(regs.orig_rax, pid);
    }

    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    log("Detached", pid);

    logFile.close();

    return 0;
}