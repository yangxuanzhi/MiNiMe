#include "myutils.hpp"

using namespace std;

string base64_encode(const unsigned char* input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

string calculate_accept_key(const string& client_key) {
    const std::string guid = WS_MAGIC;
    std::string combined_key = client_key + guid;
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(combined_key.c_str()), combined_key.length(), hash);
    return base64_encode(hash, SHA_DIGEST_LENGTH);
}

bool WebSocketFrameParser::parseFrame() {
    if (data_.size() < 2) {
        return false; // Insufficient data
    }

    // Extract the opcode and payload length
    opcode_ = data_[0] & 0x0F;
    masked_ = (data_[1] & 0x80) != 0;
    payloadLength_ = data_[1] & 0x7F;

    // Payload length may be extended
    if (payloadLength_ == 126) {
        if (data_.size() < 4) {
            return false; // Insufficient data
        }
        payloadLength_ = (static_cast<unsigned char>(data_[2]) << 8) | static_cast<unsigned char>(data_[3]);
        position_ = 4;
    } else if (payloadLength_ == 127) {
        if (data_.size() < 10) {
            return false; // Insufficient data
        }
        payloadLength_ = 0;
        for (int i = 0; i < 8; ++i) {
            payloadLength_ |= (static_cast<unsigned long long>(static_cast<unsigned char>(data_[2 + i])) << ((7 - i) * 8));
        }
        position_ = 10;
    } else {
        position_ = 2;
    }

    // Check if the frame is masked
    if (masked_) {
        if (data_.size() < position_ + 4) {
            return false; // Insufficient data
        }
        for (int i = 0; i < 4; ++i) {
            mask_[i] = data_[position_ + i];
        }
        position_ += 4;
    }

    // Extract payload data
    if (data_.size() < position_ + payloadLength_) {
        return false; // Insufficient data
    }
    payload_.resize(payloadLength_);
    for (unsigned long long i = 0; i < payloadLength_; ++i) {
        payload_[i] = data_[position_ + i] ^ mask_[i % 4];
    }

    return true;
}