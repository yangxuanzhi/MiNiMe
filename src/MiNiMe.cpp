//
// Created by aa on 4/22/24.
//

#include "MiNiMe.hpp"

using namespace std;

MiNiMe::MiNiMe() = default;

bool MiNiMe::registerUser(const string &username, const string &password)
{
    bool res = false;
    cout << "\033[34m[" << MiNiMe::getCurrentTime() << "]\033[0m "
         << "用户注册请求：" << username << ", " << password << endl;

    MYSQL *mysql = mysql_init(nullptr);
    if (mysql == nullptr) {
        cerr << "Mysql对象初始化失败!" << endl;
        exit(-1);
    }

    MYSQL *conn = mysql_real_connect(mysql, "192.168.0.182", "remote", "Mysql_abc123", "MiNiMe", 0, nullptr, 0);
    if (conn == nullptr) {
        cerr << mysql_error(mysql) << endl;
        return false;
    }

    char buf[1024] = {0};
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "select uid from user where username=\"%s\";", username.c_str());


    // 查询是否已经存在用户
    // 执行SQL语句
    if (mysql_query(conn, buf) != 0) {
        cerr << "\033[31mSQL语句" << buf << "错误\033[0m: " << mysql_error(mysql) << endl;
        mysql_close(conn);
        return false;
    } else {
        MYSQL_RES *result = mysql_store_result(conn);
        uint row_num = mysql_num_rows(result);
        if (row_num > 0) {
            cout << "\t已经存在该用户！" << endl;
            mysql_free_result(result);
            mysql_close(conn);
            return false;
        }
        mysql_free_result(result);
    }

    memset(buf, 0, sizeof(buf));
    string login_time = MiNiMe::getCurrentTime();
    sprintf(buf, R"(insert into user values(0, "%s", "%s", "%s");)", username.c_str(), password.c_str(), login_time.c_str());

    if (mysql_query(conn, buf) != 0) {
        cerr << "\033[31mSQL语句" << buf << "错误\033[0m: " << mysql_error(mysql) << endl;
    } else {
        cout << "\t用户注册成功！" << endl;
        res = true;
    }

    mysql_close(conn);
    return res;
}

tuple<int, string> MiNiMe::loginUser(const string &username, const string &password)
{
    string res;
    cout << "\033[34m[" << MiNiMe::getCurrentTime() << "]\033[0m "
         << "用户登录请求：username=" << username << ", password=" << password << endl;

    MYSQL *mysql = mysql_init(nullptr);
    if (mysql == nullptr) {
        cerr << "Mysql对象初始化失败!" << endl;
        return {-1, ""};
    }

    MYSQL *conn = mysql_real_connect(mysql, "192.168.0.182", "remote", "Mysql_abc123", "MiNiMe", 0, nullptr, 0);
    if (conn == nullptr) {
        cerr << mysql_error(mysql) << endl;
        return {-1, ""};
    }

    // 查询是否存在用户
    char buf[1024] = {0};
    memset(buf, 0, sizeof(buf));
    sprintf(buf, R"(select uid from user where username="%s" and password="%s";)", username.c_str(), password.c_str());

    string uid;
    if (mysql_query(conn, buf) != 0) {
        cerr << "\033[31mSQL语句" << buf << "错误\033[0m: " << mysql_error(mysql) << endl;
        mysql_close(conn);
        return {-1, res};
    } else {
        MYSQL_RES *result = mysql_store_result(conn);
        uint row_num = mysql_num_rows(result);
        if (row_num <= 0) {
            cout << "\t该用户不存在！" << endl;
            mysql_free_result(result);
            mysql_close(conn);
            return {-1, res};
        }
        MYSQL_ROW row;
        // 获取数据
        while ((row = mysql_fetch_row(result)) != nullptr) {
            uid = row[0];
        }
        mysql_free_result(result);
    }

    // 登录
    string login_time = MiNiMe::getCurrentTime();
    string token = generateLoginToken(username, password, login_time);

    memset(buf, 0, sizeof(buf));
    sprintf(buf, R"(update user set last_login="%s" where uid=%s)", login_time.c_str(), uid.c_str());

    if (mysql_query(conn, buf) != 0) {
        cerr << "\033[31mSQL语句" << buf << "错误\033[0m: " << mysql_error(mysql) << endl;
    }

    // 查询login_token是否存在
    memset(buf, 0, sizeof(buf));
    sprintf(buf, R"(select uid from login_token where uid=%s)", uid.c_str());

    if (mysql_query(conn, buf) != 0) {
        cerr << "\033[31mSQL语句" << buf << "错误\033[0m: " << mysql_error(mysql) << endl;
        mysql_close(conn);
        return {-1, res};
    } else {
        MYSQL_RES *result = mysql_store_result(conn);
        uint row_num = mysql_num_rows(result);
        mysql_free_result(result);
        res = token;
        if (row_num <= 0) {
            // insert
            memset(buf, 0, sizeof(buf));
            sprintf(buf, R"(insert into login_token values(%s, "%s", "%s"))", uid.c_str(), token.c_str(), login_time.c_str());

            if (mysql_query(conn, buf) != 0) {
                cerr << "\033[31mSQL语句" << buf << "错误\033[0m: " << mysql_error(mysql) << endl;
                mysql_close(conn);
                return {-1, ""};
            } else {
                char cout_buf[1024]{0};
                sprintf(cout_buf, "\t\033[34m[%s]\033[0m 用户 %s 登录成功，token为 %s！", login_time.c_str(), username.c_str(), token.c_str());
                cout << cout_buf << endl;
            }
        } else {
            // update
            memset(buf, 0, sizeof(buf));
            sprintf(buf, R"(update login_token set token="%s", login_time="%s" where uid=%s)", token.c_str(), login_time.c_str(), uid.c_str());

            if (mysql_query(conn, buf) != 0) {
                cerr << "\033[31mSQL语句" << buf << "错误\033[0m: " << mysql_error(mysql) << endl;
                mysql_close(conn);
                return {-1, ""};
            } else {
                char cout_buf[1024]{0};
                sprintf(cout_buf, "\t\033[34m[%s]\033[0m 用户%s登录成功，token为%s！", login_time.c_str(), username.c_str(), token.c_str());
                cout << cout_buf << endl;
            }
        }
    }

    mysql_close(conn);
    return {stoi(uid), res};
}

void MiNiMe::checkToken()
{
    const auto now = std::chrono::system_clock::now();
    const auto ten_minutes_ago = now - std::chrono::minutes(1);
    const std::time_t t_c = std::chrono::system_clock::to_time_t(ten_minutes_ago);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&t_c), "%Y-%m-%d %H:%M:%S");
    std::string ten_minutes_ago_str = ss.str();

    MYSQL *mysql = mysql_init(nullptr);
    if (mysql == nullptr) {
        cerr << "Mysql对象初始化失败!" << endl;
        return;
    }

    MYSQL *conn = mysql_real_connect(mysql, "192.168.0.182", "remote", "Mysql_abc123", "MiNiMe", 0, nullptr, 0);
    if (conn == nullptr) {
        cerr << mysql_error(mysql) << endl;
        return;
    }

    // 查询超时token
    char buf[1024] = {0};
    memset(buf, 0, sizeof(buf));
    sprintf(buf, R"(select uid from login_token where login_time < "%s")", ten_minutes_ago_str.c_str());

    if (mysql_query(conn, buf) != 0) {
        cerr << "\033[31mSQL语句" << buf << "错误\033[0m: " << mysql_error(mysql) << endl;
        mysql_close(conn);
        return;
    } else {
        MYSQL_RES *result = mysql_store_result(conn);
        uint row_num = mysql_num_rows(result);
        if (row_num <= 0) {
            mysql_free_result(result);
            mysql_close(conn);
            return;
        }
        MYSQL_ROW row;
        // 获取数据
        cout << "\033[34m[" << MiNiMe::getCurrentTime() << "]\033[0m" << "用户 \033[33m";
        while ((row = mysql_fetch_row(result)) != nullptr) {
            cout << row[0] << " ";
        }
        cout << "\033[0m超时下线" << endl;
        mysql_free_result(result);
    }

    // 删除所有token过期的用户
    buf[1024] = {0};
    memset(buf, 0, sizeof(buf));
    sprintf(buf, R"(delete from login_token where login_time < "%s")", ten_minutes_ago_str.c_str());

    if (mysql_query(conn, buf) != 0) {
        cerr << "\033[31mSQL语句" << buf << "错误\033[0m: " << mysql_error(mysql) << endl;
    }

    mysql_close(conn);
}

MiNiMe::~MiNiMe() = default;

string MiNiMe::generateLoginToken(const string &username, const string &password, const string &login_time) {
    // 将用户名和密码拼接在一起
    string data = username + password + login_time;

    // 使用 SHA256 哈希算法计算哈希值
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);

    // 将哈希值转换为十六进制字符串作为 token
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH && ss.str().size() < 50; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

string MiNiMe::getCurrentTime() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t_c = std::chrono::system_clock::to_time_t(now);
    stringstream ss;
    ss << put_time(std::localtime(&t_c), "%Y-%m-%d %H:%M:%S");
    string login_time = ss.str();
    return login_time;
}