#pragma once

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <string>
#include <vector>

#define WS_MAGIC "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" // WebSocket Magic String
// WebSocket opcode
#define WS_OPCODE_CONTINUATION 0x00
#define WS_OPCODE_TEXT         0x01
#define WS_OPCODE_BINARY       0x02
#define WS_OPCODE_CLOSE        0x08
#define WS_OPCODE_PING         0x09
#define WS_OPCODE_PONG         0x0A


std::string base64_encode(const unsigned char* input, int length);

std::string calculate_accept_key(const std::string& client_key);

class WebSocketFrameParser {
public:
    WebSocketFrameParser(const std::vector<char>& data) : data_(data), position_(0) {}

    // Parse WebSocket frame
    bool parseFrame();

    // Get opcode
    unsigned char getOpcode() const {
        return opcode_;
    }

    // Get masked flag
    bool isMasked() const {
        return masked_;
    }

    // Get payload length
    unsigned long long getPayloadLength() const {
        return payloadLength_;
    }

    // Get payload data
    const std::vector<char>& getPayload() const {
        return payload_;
    }

private:
    std::vector<char> data_;
    size_t position_;
    unsigned char opcode_;
    bool masked_;
    unsigned long long payloadLength_;
    char mask_[4];
    std::vector<char> payload_;
};

std::vector<char> wrapWebSocketFrame(const std::string& payload, unsigned char opcode);