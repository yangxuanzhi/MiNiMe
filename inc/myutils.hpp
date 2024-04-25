#pragma once

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <string>
#include <vector>

#define WS_MAGIC "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" // WebSocket Magic String

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