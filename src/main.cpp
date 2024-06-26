#include <csignal>
#include <cstdlib>
#include <cstring>

#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <unordered_map>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/event_struct.h>
#include <event2/http_struct.h>
#include <evbuffer_internal.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "configor/json.hpp"

#include "MiNiMe.hpp"
#include "log.hpp"
#include "myutils.hpp"

#define __DEBUG__ true

using namespace std;

MiNiMe controller;
event_base *base;

struct websocket_event {
    int uid=-1;
    bufferevent *bev;
    event *tev;
    time_t lastActive;
};

unordered_map<bufferevent*, websocket_event*> *bev_wev;
unordered_map<int, websocket_event*> *uid_wev;

/************************************ 全局工具函数 *****************************************/

static void send_response(evhttp_request *req, int code, const char *reason, const string& data) {
    struct evbuffer *reply = evbuffer_new();

    evbuffer_add_printf(reply, "%s", data.c_str());
    evhttp_send_reply(req, code, reason, reply);
    evbuffer_free(reply);
}

/************************************ HTTP回调函数 *****************************************/

static void timer_cb(evutil_socket_t fd, short ev, void *arg) {
    if (!__DEBUG__) {
        controller.checkToken();

        size_t batch = bev_wev->size() / 10;
        size_t all = bev_wev->size();
        time_t curTime = time(0);
        auto iter = bev_wev->begin();
        for (int j = 0; j < batch; j++) {
            if (iter == bev_wev->end()) {
                iter = bev_wev->begin();
                continue;
            }
            bufferevent *bev = iter->first;
            websocket_event *wev = iter->second;
            if (wev->lastActive + 60 < curTime || (wev->lastActive + 30 < curTime && wev->uid == -1)) {
                bufferevent_free(bev);
                if (wev->uid >= 0) uid_wev->erase(wev->uid);
                if (wev->tev) event_free(wev->tev);
                free(wev);
                bev_wev->erase(bev);
            }
        }
    }

    timeval tv{1, 0};
    evtimer_add((event*)arg, &tv);
}

static void signal_cb(evutil_socket_t fd, short event, void *arg)
{
    stringstream ss;
    ss << strsignal(fd) << " signal received";
    mywarn(ss.str());
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
        send_response(req, 400, nullptr, R"({"code":400, "op":"login", "info":"Invalid Request Length!"})");
        evbuffer_free(eb);
        return;
    }

    char buf[1024]{0};
    if (-1 == evbuffer_remove(eb, buf, sizeof(buf))) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"login", "info":"Invalid Request!"})");
        evbuffer_free(eb);
        return;
    }

    char *decoded_body = evhttp_uridecode(buf, 0, &len);
    if (decoded_body == nullptr) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"login", "info":"Invalid Request!"})");
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
        send_response(req, 400, nullptr, R"({"code":400, "op":"login", "info":"Invalid Username Length!"})");
        return;
    }

    char *password_ = strstr(buf, "password=") + 9;
    string password{};
    for (size_t i = 0; *(password_+i) != '\0' && *(password_+i) != '&'; i++) {
        password += *(password_ + i);
    }
    if (password.size() > 50 || password.empty()) {
        send_response(req, 400, nullptr, R"({"code":400, "op":"login", "info":"Invalid Password Length!"})");
        return;
    }

    auto [uid, token] = controller.loginUser(username, password);
    if (!token.empty()) {
        configor::json::value json_data = configor::json::object{
            { "code", 200 },
            { "op", "login"},
            { "uid", uid},
            { "token", token}
        };
        send_response(req, 200, nullptr, configor::json::dump(json_data));
    } else {
        send_response(req, 400, nullptr, R"({"code":400, "op":"login", "info":"Wrong Username Or Password!"})");
    }
}

/************************************ WebSocket回调函数 *****************************************/

static void websocket_timer_cb(evutil_socket_t fd, short ev, void *arg) {
    websocket_event *wev = (websocket_event*)arg;

    if (!__DEBUG__) {
        vector<char> wspack = wrapWebSocketFrame("", WS_OPCODE_PING);
        bufferevent_write(wev->bev, wspack.data(), wspack.size());
    }

    timeval tv{10, 0};
    evtimer_add(wev->tev, &tv);
}

void read_cb(struct bufferevent *bev, void *ctx) {
    // 读取消息
    stringstream logss;
    char buf[4096];
    size_t len = bufferevent_read(bev, buf, sizeof(buf) - 1);
    buf[len] = '\0';
    logss << "WebSocket服务器请求接到来自 ";

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    evutil_socket_t sockfd = bufferevent_getfd(bev);

    if (getpeername(sockfd, (struct sockaddr*)&addr, &addr_len) == -1) {
        perror("getsockname");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 打印本地地址信息
    char ip[INET_ADDRSTRLEN];
    logss << inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip)) << ":";
    logss << ntohs(addr.sin_port) << " 的消息：";
    

    // 判断是否是握手信息
    if (strstr(buf, "Upgrade: websocket") != NULL 
        && strstr(buf, "Connection: Upgrade") != NULL) {
        logss << buf;
        mylog(logss.str());
        // Find the value of Sec-WebSocket-Key
        char *key_start = strstr(buf, "Sec-WebSocket-Key: ");
        if (key_start != NULL) {
            key_start += strlen("Sec-WebSocket-Key: ");
            char *key_end = strchr(key_start, '\r');
            if (key_end != NULL) {
                *key_end = '\0';

                // Calculate Sec-WebSocket-Accept
                string accept_key = calculate_accept_key(string(key_start));
                
                // Construct the handshake response
                const char *response_template = "HTTP/1.1 101 Switching Protocols\r\n"
                                                "Upgrade: websocket\r\n"
                                                "Connection: Upgrade\r\n"
                                                "Sec-WebSocket-Accept: %s\r\n"
                                                "\r\n";
                char response[256];
                snprintf(response, sizeof(response), response_template, accept_key.c_str());
                
                // 发送websocket握手响应
                bufferevent_write(bev, response, strlen(response));

                // 设置连接检测
                event *timer_ev = new event;
                (*bev_wev)[bev]->tev = timer_ev;
                evtimer_assign(timer_ev, base, websocket_timer_cb, (*bev_wev)[bev]);

                timeval tv{10, 0};
                evtimer_add(timer_ev, &tv);
                return;
            }
        }
    }
    else {
        // Websocket消息处理
        vector<char> wspack;
        for (int i = 0; i < len; i++) {
            wspack.push_back(buf[i]);
        }
        size_t n;
        while ((n = bufferevent_read(bev, buf, sizeof(buf))) > 0) {
            // printf("Received: %.*s", (int)n, buf);
            for (int i = 0; i < n; i++) {
                wspack.push_back(buf[i]);
            }
        }
        WebSocketFrameParser parser(wspack);
        if (parser.parseFrame()) {
            // stringstream ss;
            // ss << "接收到Websocket消息，长度：" << parser.getPayloadLength()
            //    << "，类型：" << parser.getOpcode() << "，内容：";
            unsigned char opcode = parser.getOpcode();
            if (opcode == WS_OPCODE_PONG) {
                (*bev_wev)[bev]->lastActive = time(0);
                return;
            }
            auto& payload = parser.getPayload();

            stringstream ss;
            for (int i = 0; i < parser.getPayloadLength(); i++) {
                ss << payload[i];
            }
            mylog(logss.str() + ss.str());

            configor::json::value json_data = configor::json::parse(ss.str());
            string ws_op = (string)json_data["op"];
            if (ws_op == "login") {
                int uid = (int)json_data["uid"];
                string token = (string)json_data["token"];
                if (controller.checkUidToken(uid, token)) {
                    (*uid_wev)[uid] = (*bev_wev)[bev];
                }
                else {
                    websocket_event *wev = (*bev_wev)[bev];
                    bufferevent_free(bev);
                    if (wev->uid >= 0) uid_wev->erase(wev->uid);
                    if (wev->tev) event_free(wev->tev);
                    free(wev);
                    bev_wev->erase(bev);
                }
            }
            
        }
        else {
            mylog(logss.str());
            mywarn("无法解析接收到的Websocket消息！");
        }
    }
}

void event_cb(struct bufferevent *bev, short events, void *ctx) {
    if (events & BEV_EVENT_ERROR) {
        perror("Error");
    }
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
    }
}

void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx) {
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    websocket_event* wev = new websocket_event;
    wev->bev = bev;
    wev->lastActive = time(0);
    (*bev_wev)[bev] = wev;
    bufferevent_setcb(bev, read_cb, nullptr, event_cb, NULL);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

void accept_error_cb(struct evconnlistener *listener, void *ctx) {
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Error %d (%s) on the listener. Shutting down.\n", err, evutil_socket_error_to_string(err));
    event_base_loopexit(base, NULL);
}

int main()
{
    controller = MiNiMe();

    bev_wev = new unordered_map<bufferevent*, websocket_event*>();
    uid_wev = new unordered_map<int, websocket_event*>();

    base = event_base_new();

    // HTTP服务器
    ev_uint16_t http_port = 8080;
    char http_addr[] = "0.0.0.0";
    
    evhttp *http_server = evhttp_new(base);

    evhttp_bind_socket(http_server, http_addr, http_port);

    evhttp_set_cb(http_server, "/register", register_request_handler, nullptr);
    evhttp_set_cb(http_server, "/login", login_request_handler, nullptr);
    evhttp_set_gencb(http_server, generic_request_handler, nullptr);

    event *sig_int = evsignal_new(base, SIGINT, signal_cb, base);
    event_add(sig_int, nullptr);

    event *timer_ev = new event;
    evtimer_assign(timer_ev, base, timer_cb, timer_ev);

    timeval tv{1, 0};
    evtimer_add(timer_ev, &tv);

    {
        stringstream ss;
        ss << "HTTP服务器开始监听 " << http_addr << ":" << http_port;
        mylog(ss.str());
    }

    // Websocket服务器
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0); // Listen on all interfaces
    sin.sin_port = htons(3000);

    struct evconnlistener *listener = evconnlistener_new_bind(base, accept_conn_cb, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin));
    if (!listener) {
        myerr("Websocket监听服务创建失败！");
        return 1;
    }

    evconnlistener_set_error_cb(listener, accept_error_cb);

    mylog("Wesocket服务器开始监听 0.0.0.0:3000");

    event_base_dispatch(base);

    evhttp_free(http_server);
    event_free(sig_int);
    event_base_free(base);
}