#include "log.hpp"

void mylog(string info)
{
    cout << "\033[34m[" << MiNiMe::getCurrentTime() << "]\033[0m "
         << info << endl;
}

void mywarn(string info)
{
    cout << "\033[33m[" << MiNiMe::getCurrentTime() << "]\033[0m "
         << info << endl;
}

void myerr(string info)
{
    cerr << "\033[31m[" << MiNiMe::getCurrentTime() << "]\033[0m "
         << info << endl;
}
