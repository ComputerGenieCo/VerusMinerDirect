#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include "main.h"

#ifndef WIN32
static void signal_handler(int sig)
{
    switch (sig)
    {
    case SIGHUP:
        applog(LOG_INFO, "SIGHUP received");
        break;
    case SIGINT:
        signal(sig, SIG_IGN);
        applog(LOG_INFO, "SIGINT received, exiting");
        proper_exit(EXIT_CODE_KILLED);
        break;
    case SIGTERM:
        applog(LOG_INFO, "SIGTERM received, exiting");
        proper_exit(EXIT_CODE_KILLED);
        break;
    }
}
#else
BOOL WINAPI ConsoleHandler(DWORD dwType)
{
    switch (dwType)
    {
    case CTRL_C_EVENT:
        applog(LOG_INFO, "CTRL_C_EVENT received, exiting");
        proper_exit(EXIT_CODE_KILLED);
        break;
    case CTRL_BREAK_EVENT:
        applog(LOG_INFO, "CTRL_BREAK_EVENT received, exiting");
        proper_exit(EXIT_CODE_KILLED);
        break;
    case CTRL_LOGOFF_EVENT:
        applog(LOG_INFO, "CTRL_LOGOFF_EVENT received, exiting");
        proper_exit(EXIT_CODE_KILLED);
        break;
    case CTRL_SHUTDOWN_EVENT:
        applog(LOG_INFO, "CTRL_SHUTDOWN_EVENT received, exiting");
        proper_exit(EXIT_CODE_KILLED);
        break;
    default:
        return false;
    }
    return true;
}
#endif

void setup_signal_handlers()
{
#ifndef WIN32
    /* Always catch Ctrl+C */
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGTERM, signal_handler);
#else
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE);
#endif
}
