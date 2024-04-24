//
// Created by aa on 4/22/24.
//

#ifndef MINIME_MINIME_HPP
#define MINIME_MINIME_HPP

#include <cstdio>
#include <cstring>

#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <tuple>

#include <openssl/sha.h>
#include <mysql.h>
using namespace std;

class MiNiMe {
public:
    MiNiMe();

    /**
     * 用户注册服务函数，输入uid和密码，返回注册是否成功
     * @param username 用户唯一id
     * @param password 密码
     * @return 注册是否成功
     */
    bool registerUser(const string &username, const string &password);

    /**
     * 用户登录服务函数
     * @param username 用户id
     * @param password 密码
     * @return 登陆成功返回token
     */
    tuple<int, string> loginUser(const string &username, const string &password);

    void checkToken();

    ~MiNiMe();
    
    static string getCurrentTime();
private:
    static string generateLoginToken(const std::string &username, const std::string &password, const string &login_time);
};


#endif //MINIME_MINIME_HPP
