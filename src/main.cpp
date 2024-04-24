#include <csignal>
#include <cstdlib>
#include <cstring>

#include <iostream>
#include <memory>
#include <string>
#include <sstream>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/event_struct.h>
#include <event2/http_struct.h>
#include <evbuffer_internal.h>

#include "MiNiMe.hpp"

using namespace std;

MiNiMe controller;

static void send_response(evhttp_request *req, int code, const char *reason, const string& data) {
    struct evbuffer *reply = evbuffer_new();

    evbuffer_add_printf(reply, "%s", data.c_str());
    evhttp_send_reply(req, code, reason, reply);
    evbuffer_free(reply);
}

static void signal_cb(evutil_socket_t fd, short event, void *arg)
{
    printf("%s signal received\n", strsignal(fd));
    event_base_loopbreak((event_base*)arg);
}

static void generic_request_handler(struct evhttp_request *req, void *arg) {
    send_response(req, 404, nullptr, R"({"code":404, "info":"Not Found!"})");
}

static void register_request_handler(evhttp_request *req, void *arg) {
    // 获取请求内容
    evbuffer *eb = evhttp_request_get_input_buffer(req);

    size_t len = evbuffer_get_length(eb);
    if (len <= 0 || len > 1024) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"Invalid Request Length!"})");
        evbuffer_free(eb);
        return;
    }

    char buf[1024]{0};
    if (-1 == evbuffer_remove(eb, buf, sizeof(buf))) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"Invalid Request!"})");
        evbuffer_free(eb);
        return;
    }

    char *decoded_body = evhttp_uridecode(buf, 0, &len);
    if (decoded_body == nullptr) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"Invalid Request!"})");
        return;
    }
    memset(buf, 0, sizeof(buf));
    strcpy(buf, decoded_body);

    char *username_ = strstr(buf, "username=") + 9;
    string username{};
    for (size_t i = 0; *(username_+i) != '\0' && *(username_+i) != '&'; i++) {
        username += *(username_ + i);
    }
    if (username.size() > 50 || username.empty()) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"Invalid Username Length!"})");
        return;
    }

    char *password_ = strstr(buf, "password=") + 9;
    string password{};
    for (size_t i = 0; *(password_+i) != '\0' && *(password_+i) != '&'; i++) {
        password += *(password_ + i);
    }
    if (password.size() > 50 || password.empty()) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"Invalid Password Length!"})");
        return;
    }

    if (controller.registerUser(username, password)) {
        send_response(req, 200, nullptr, R"({"code":200, "op":"register"})");
    } else {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"User Exists!"})");
    }
}

static void login_request_handler(evhttp_request *req, void *arg) {
    // 获取请求内容
    evbuffer *eb = evhttp_request_get_input_buffer(req);

    size_t len = evbuffer_get_length(eb);
    if (len <= 0 || len > 1024) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"Invalid Request Length!"})");
        evbuffer_free(eb);
        return;
    }

    char buf[1024]{0};
    if (-1 == evbuffer_remove(eb, buf, sizeof(buf))) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"Invalid Request!"})");
        evbuffer_free(eb);
        return;
    }

    char *decoded_body = evhttp_uridecode(buf, 0, &len);
    if (decoded_body == nullptr) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"Invalid Request!"})");
        return;
    }
    memset(buf, 0, sizeof(buf));
    strcpy(buf, decoded_body);

    char *username_ = strstr(buf, "username=") + 9;
    string username{};
    for (size_t i = 0; *(username_+i) != '\0' && *(username_+i) != '&'; i++) {
        username += *(username_ + i);
    }
    if (username.size() > 50 || username.empty()) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"Invalid Username Length!"})");
        return;
    }

    char *password_ = strstr(buf, "password=") + 9;
    string password{};
    for (size_t i = 0; *(password_+i) != '\0' && *(password_+i) != '&'; i++) {
        password += *(password_ + i);
    }
    if (password.size() > 50 || password.empty()) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"Invalid Password Length!"})");
        return;
    }

    auto [uid, token] = controller.loginUser(username, password);
    if (!token.empty()) {
        stringstream data;
        data << R"({"code":200, "op":"login", "uid":)" << uid << R"(, "token":")" << token << "\"}";
        send_response(req, 200, nullptr, data.str());
    } else {
        send_response(req, 400, nullptr, R"({"code":400, "op":"register", "info":"Wrong Username Or Password!"})");
    }
}

int main()
{
    controller = MiNiMe();

    ev_uint16_t http_port = 8080;
    char http_addr[] = "0.0.0.0";
    event_base *base = event_base_new();
    evhttp *http_server = evhttp_new(base);

    evhttp_bind_socket(http_server, http_addr, http_port);

    evhttp_set_cb(http_server, "/register", register_request_handler, nullptr);
    evhttp_set_cb(http_server, "/login", login_request_handler, nullptr);
    evhttp_set_gencb(http_server, generic_request_handler, nullptr);

    event *sig_int = evsignal_new(base, SIGINT, signal_cb, base);
    event_add(sig_int, nullptr);

    cout << "开始监听 " << http_addr << ":" << http_port << endl;

    event_base_dispatch(base);

    evhttp_free(http_server);
    event_free(sig_int);
    event_base_free(base);
}