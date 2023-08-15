#ifndef _DIFC_MECHANISM_DIFC_HPP
#define _DIFC_MECHANISM_DIFC_HPP

#include "dmaabe/comms.hpp"
#include "dmaabe/encryptor.hpp"
#include "dmaabe/decryptor.hpp"

#include "difc_interfaces/srv/difc_request.hpp"
#include "cereal/archives/portable_binary.hpp"

#include "rclcpp/rclcpp.hpp"
#include "rclcpp/context.hpp"

#include <sys/mman.h>

#include <unordered_map>
#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <chrono>
#include <unistd.h>
#include <chrono>
#include <fstream>
#define CLOCK_RATE 3400UL

using namespace std::chrono_literals;

// static inline uint64_t rdtsc()
// {
//     uint32_t lo, hi;
//     __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
//     return ((uint64_t)hi << 32) | lo;
// }

namespace rclcpp
{

SerializedMessage difc_decrypt(
    const SerializedMessage & msg
);

SerializedMessage difc_encrypt(
    const SerializedMessage & msg,
    const std::string & topic
);

}

namespace difc_mechanism {

std::function<std::pair<bool, bool>(const std::vector<unsigned char> &)> difc_function = 
    [](const std::vector<unsigned char> & vec){
        (void) vec;
        return std::make_pair(true, false);
    };

std::function<std::vector<unsigned char>(const dmaabe::Attribute &)> request_function =
    [](const dmaabe::Attribute & attr) {
        (void) attr;
        return std::vector<unsigned char>();
    };

std::string
load_public_coin(const std::string & public_coin_file_path = "")
    {
        std::ifstream public_coin_file_handle(public_coin_file_path);
        std::stringstream pub_coin_str;
        pub_coin_str << public_coin_file_handle.rdbuf();
        return "Public_Coin";
    }

struct KeyRequest {
    std::string requester_pid;
    dmaabe::Attribute attr_reqd;
    std::vector<unsigned char> metadata;

    template<class Archive>
    void
    serialize(Archive & ar) {
        ar(requester_pid, attr_reqd, metadata);
    }
};

struct OSReportKey {
    std::vector<unsigned char> ser_enc_key;
    std::string pid;
    bool declassify;

    template<class Archive>
    void
    serialize(Archive & ar) {
        ar(ser_enc_key, pid, declassify);
    }
};

struct SignedOSReportKey {
    OSReportKey key;
    std::string os_key_sig;

    template<class Archive>
    void
    serialize(Archive & ar) {
        ar(key, os_key_sig);
    }
};

struct KeyResponse {
    std::vector<unsigned char> ser_dec_key;
    SignedOSReportKey signed_os_key_data;

    template<class Archive>
    void
    serialize(Archive & ar) {
        ar(ser_dec_key, signed_os_key_data);
    }
};

class ProcessDIFCManager {

    private:
        static void* memory_location;
        static size_t * num_keys_ptr;
        static dmaabe::PtrWithLen* keys_ptr;
        static unsigned char* last_location;

        static
        void 
        lkm_memory_init()
            {
                constexpr const size_t MEMORY_SIZE = 1000000;
                memory_location = mmap(NULL, MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
                if(memory_location == MAP_FAILED)
                    throw std::exception();
                num_keys_ptr = (size_t*) (memory_location);
                *num_keys_ptr = 0;
                keys_ptr = (dmaabe::PtrWithLen*) (void*)((char*)(memory_location) + sizeof(size_t));
                last_location =((unsigned char*)(num_keys_ptr) + 300*sizeof(dmaabe::PtrWithLen) + sizeof(size_t));
                std::cout << "LKM Memory Init done." << std::endl;
            }

        static   
        void
        report_to_os(const SignedOSReportKey & os_report_key)
        {

            dmaabe::PtrWithLen* current_last = keys_ptr + *num_keys_ptr;      
            std::string val_str(os_report_key.key.ser_enc_key.begin(), os_report_key.key.ser_enc_key.end());
            std::memcpy(last_location, val_str.c_str(), val_str.size());
            *current_last ={
                .len = val_str.size(),
                .ptr = last_location 
            };
            last_location += val_str.size() + 1;
            ++*num_keys_ptr;

            // auto difc_requester_node = std::make_shared<rclcpp::Node>("pid_" + pid + "_verifierclient");
            // auto service_client = difc_requester_node.get() -> create_client<difc_interfaces::srv::DIFCRequest>("/verifier");
            // auto req_ptr = std::make_shared<difc_interfaces::srv::DIFCRequest::Request>();
            // req_ptr -> req_type = 0x00;
            // req_ptr -> request = dmaabe::convert_to_vector(os_report_key);
            // while (!service_client->wait_for_service(1s)) {
            //     if (!rclcpp::ok()) {
            //         std::cout << "Interrupted while waiting for the service. Exiting." << std::endl;
            //         break;
            //     }
            //     std::cout << "service not available, waiting again..." << std::endl;
            // }
            // auto future_result = service_client -> async_send_request(req_ptr);
            // std::cout << "request sent to /verifier" << std::endl;
            // if(rclcpp::spin_until_future_complete(difc_requester_node, future_result) == rclcpp::FutureReturnCode::SUCCESS) {
            //     auto res = future_result.get();
            //     if(res -> response_status == 0) {
            //         std::cout << "Report successful" << std::endl;
            //     }
            //     else {
            //         std::cout << "Report not successful" << std::endl;
            //     }
            // }

        }

        

    public:
        static std::string enclave_name;
        static std::string pid;
        static std::unordered_map<std::string, bool> read_permissions;
        static std::string private_nonce_str;
        static std::unordered_map<std::string, dmaabe::Attribute> topic_attr_map;
        static bool masked;
        // std::shared_ptr<rclcpp::Node> difc_requester_node;
        // std::shared_ptr<rclcpp::Service<difc_interfaces::srv::DIFCRequest>> difc_key_gen_service;

        ProcessDIFCManager(const std::string & public_coin, const std::string & enclave_name_ = std::string(), const bool & masked_ = true) {
            process_difc_manager_init(public_coin, enclave_name_, masked_);
        }


        static
        void
        process_difc_manager_init(const std::string & public_coin, const std::string & enclave_name_ = std::string(), const bool & masked_ = true) {
                pid = std::to_string(getpid());
                enclave_name = enclave_name_;
                lkm_memory_init();
                masked = masked_;
                dmaabe::init(public_coin, memory_location, pid);
                if(masked) {
                    mcl::bn::Fr nonce_num;
                    nonce_num.setByCSPRNG();
                    private_nonce_str = nonce_num.serializeToHexStr();
                }
        }

        dmaabe::Ciphertext
        difc_encrypt(
            const rclcpp::SerializedMessage & message, 
            const std::string & topic
        )
        {
            // std::cout << "Inside difc encrypt" << std::endl;
            auto & rcl_handle = message.get_rcl_serialized_message();
            std::vector<unsigned char> vec_message;
            vec_message.reserve(rcl_handle.buffer_length);
            for(size_t len = 0; len < rcl_handle.buffer_length; ++len)
                vec_message.push_back((unsigned char)*(rcl_handle.buffer + len));
            
            if(!enclave_name.empty()) {
                if(topic_attr_map.find(topic) == topic_attr_map.end()) {
                    if(masked) {
                        auto priv_str = topic + private_nonce_str;
                        mcl::bn::Fr hashed_topic_str;
                        hashed_topic_str.setHashOf(priv_str);
                        topic_attr_map[topic] =  pid + "." + enclave_name + "." + hashed_topic_str.serializeToHexStr();
                    }
                    else {
                        topic_attr_map[topic] = pid + "." + enclave_name + "." + topic;
                    }
                    
                    dmaabe::load_attrs({topic_attr_map[topic]});
                    auto priv_key_to_report = dmaabe::get_private_key_for(topic_attr_map[topic]);
                    auto difc_requester_node = std::make_shared<rclcpp::Node>("pid_" + pid + "_difcrequester");
                    auto service_client = difc_requester_node.get() -> create_client<difc_interfaces::srv::DIFCRequest>(enclave_name + "_difckeygen");
                    auto req_ptr = std::make_shared<difc_interfaces::srv::DIFCRequest::Request>();
                    req_ptr -> req_type = 0x02;
                    req_ptr -> request = dmaabe::convert_to_vector(priv_key_to_report);
                    while (!service_client->wait_for_service(1s)) {
                        if (!rclcpp::ok()) {
                            std::cout << "[PICAROS]: Interrupted while waiting for the service. Exiting." << std::endl;
                            break;
                        }
                        std::cout << "[PICAROS]: service not available, waiting again..." << std::endl;
                    }
                    auto future_result = service_client -> async_send_request(req_ptr);
                    std::cout << "[PICAROS]: request sent to " << enclave_name + "_difckeygen" << std::endl;
                    if(rclcpp::spin_until_future_complete(difc_requester_node, future_result) == rclcpp::FutureReturnCode::SUCCESS) {
                        auto res = future_result.get();
                        if(res -> response_status == 0) {
                            std::cout << "[PICAROS]: Report successful" << std::endl;
                        }
                        else {
                            std::cout << "[PICAROS]: Report not successful" << std::endl;
                        }
                    }
                }
            }
            else {
                topic_attr_map[topic] = topic;
            }
            dmaabe::Ciphertext encrypted;
            if(enclave_name.empty()) {                
                encrypted = dmaabe::encrypt_from_os(dmaabe::encode(vec_message));
            }
            else {
                // std::cout << topic << std::endl;
                // std::cout << topic_attr_map[topic] << std::endl;
                encrypted = dmaabe::encrypt_from_os_and_self(dmaabe::encode(vec_message), topic_attr_map[topic]); 
            }
            return encrypted;
        }

        std::vector<unsigned char>
        difc_decrypt(
            const dmaabe::Ciphertext & cipher
        )
        {
            auto all_keys = cipher.attrs;
            std::vector<dmaabe::Attribute> permissions_needed;
            for(const auto & attr : all_keys) {
                if (read_permissions.find(attr) == read_permissions.end()) {
                    permissions_needed.push_back(attr);
                }
            }

            if(!permissions_needed.empty()) {
                for(const auto & attr : permissions_needed) {

                    std::stringstream str_str(attr);
                    std::string segment;
                    std::vector<std::string> segvec;
                    while(std::getline(str_str, segment, '.')) {
                        segvec.push_back(segment);
                    }

                    auto pid_to_req = segvec[1];
                    KeyRequest key_req = {
                        .requester_pid = pid,
                        .attr_reqd = attr,
                        .metadata =  request_function(attr)
                    };
                    auto difc_requester_node = std::make_shared<rclcpp::Node>("pid_" + pid + "_difcrequester");
                    auto service_client = difc_requester_node.get() -> create_client<difc_interfaces::srv::DIFCRequest>(pid_to_req + "_difckeygen");
                    auto req_ptr = std::make_shared<difc_interfaces::srv::DIFCRequest::Request>();
                    req_ptr -> req_type = 0x01;
                    req_ptr -> request = dmaabe::convert_to_vector(key_req);
                    while (!service_client->wait_for_service(1s)) {
                        if (!rclcpp::ok()) {
                            std::cout << "[PICAROS]: Interrupted while waiting for the service. Exiting." << std::endl;
                            break;
                        }
                        std::cout << "[PICAROS]: service not available, waiting again..." << std::endl;
                    }
                    auto future_result = service_client -> async_send_request(req_ptr);
                    std::cout << "[PICAROS]: request sent to " << pid_to_req + "_difckeygen" << std::endl;
                    if(rclcpp::spin_until_future_complete(difc_requester_node, future_result) == rclcpp::FutureReturnCode::SUCCESS) {
                        auto res = future_result.get();
                        if(res -> response_status == 0) {
                            auto key_resp = dmaabe::convert_from_vector<KeyResponse>(res -> response);
                            report_to_os(key_resp.signed_os_key_data);
                            auto decryption_key = dmaabe::convert_from_vector<dmaabe::DecryptionKey>(key_resp.ser_dec_key);
                            dmaabe::load_dec_key(decryption_key.attr, decryption_key);
                            read_permissions[attr] = true;
                        }
                        else {
                            read_permissions[attr] = false;
                        }
                    }

                }
            }

            bool all_permissions = true;
            for(const auto & attr : cipher.attrs) {
                all_permissions &= read_permissions[attr];
            }

            if(all_permissions)
                return dmaabe::decode(dmaabe::decrypt(cipher));
            
            return std::vector<unsigned char>();
        }

};

}

using difc_mechanism::ProcessDIFCManager;

std::string ProcessDIFCManager::enclave_name = std::string();
std::unordered_map<std::string, bool> ProcessDIFCManager::read_permissions = std::unordered_map<std::string, bool>();

bool ProcessDIFCManager::masked = true;
std::string ProcessDIFCManager::pid = "";
std::string ProcessDIFCManager::private_nonce_str = "";

std::unordered_map<std::string, dmaabe::Attribute> ProcessDIFCManager::topic_attr_map;

void* ProcessDIFCManager::memory_location = nullptr;
size_t* ProcessDIFCManager::num_keys_ptr = nullptr;
dmaabe::PtrWithLen* ProcessDIFCManager::keys_ptr = nullptr;
unsigned char* ProcessDIFCManager::last_location = nullptr;

ProcessDIFCManager* difc_manager_ptr = nullptr;

namespace rclcpp{

void difc_init(const std::string & enclave_name_)
    {
        std::string public_coin = difc_mechanism::load_public_coin();
        difc_manager_ptr = new difc_mechanism::ProcessDIFCManager(public_coin, enclave_name_);
    }

SerializedMessage
difc_encrypt(
    const rclcpp::SerializedMessage & plaintext,
    const std::string & topic_name
)
{
    // std::cout << "Plaintext Message: " << plaintext.get_rcl_serialized_message().buffer << std::endl;    
    auto cipher = difc_manager_ptr -> difc_encrypt(plaintext, topic_name);
    // std::cout << "Outside E1: " << cipher.ser_E1 << std::endl;
    auto vectorized_cipher = dmaabe::convert_to_vector<dmaabe::Ciphertext>(cipher);
    // std::cout << "Ciphertext Size: " << vectorized_cipher.size() << std::endl;
    std::string temp_str(vectorized_cipher.begin(), vectorized_cipher.end());
    // std::cout << "Cipher text of size: " << vectorized_cipher.size() << std::endl;
    rclcpp::SerializedMessage ser_cipher(temp_str.size() + 1);
    auto & rcl_handle = ser_cipher.get_rcl_serialized_message();
    // for(size_t i = 0; i < vectorized_cipher.size(); ++i) {
    //     *(rcl_handle->buffer + i) = vectorized_cipher[i];
    //     std::cout << *(rcl_handle->buffer + i);
    // }
    std::memcpy(rcl_handle.buffer, temp_str.c_str(), temp_str.size());
    // std::cout << "Encrypted: " << temp_str << std::endl;
    rcl_handle.buffer[temp_str.size()] = '\0';
    rcl_handle.buffer_length = temp_str.size() + 1;
    // std::cout << "Buffer Written: " << ser_cipher.size() << std::endl;
    // for(size_t i = 0; i < ser_cipher.size(); i += 1)
    //     std::cout << ser_cipher.get_rcl_serialized_message().buffer[i];
    return ser_cipher;
    // std::this_thread::sleep_for(std::chrono::milliseconds(2));
    // return plaintext;
}


SerializedMessage
difc_decrypt(
    const rclcpp::SerializedMessage & ciphertext
)
{
    const auto & rcl_handle = ciphertext.get_rcl_serialized_message();
    std::vector<unsigned char> cipher_vec;
    // std::cout << "Buffer received: " << rcl_handle.buffer_length << std::endl;
    cipher_vec.reserve(rcl_handle.buffer_length - 1);
    for(size_t i = 0; i < rcl_handle.buffer_length - 1; ++i)
        cipher_vec.push_back(rcl_handle.buffer[i]);
    // if(rcl_handle.buffer[rcl_handle.buffer_length -2] != '\0')
    //     throw std::exception();
        // std::cout << "Check passed." << std::endl;
    // std::cout << "Vector Written of size " << cipher_vec.size() << std::endl;
    auto cipher = dmaabe::convert_from_vector<dmaabe::Ciphertext>(cipher_vec);
    auto plaintext = difc_manager_ptr -> difc_decrypt(cipher);
    std::string temp_str(plaintext.begin(), plaintext.end());
    // std::cout << "Decrypted: " << temp_str << std::endl;
    rclcpp::SerializedMessage decrypted(temp_str.size() + 1);
    auto & rcl_handle_2 = decrypted.get_rcl_serialized_message();
    std::memcpy(rcl_handle_2.buffer, temp_str.c_str(), temp_str.size());
    rcl_handle_2.buffer[temp_str.size()] = '\0';
    rcl_handle_2.buffer_length = temp_str.size() + 1;
    return decrypted;
    // std::this_thread::sleep_for(std::chrono::milliseconds(1));
    // return ciphertext;
}
void
load_difc_function(const std::function<std::pair<bool, bool>(const std::vector<unsigned char> &)> & difc_function_) {
    difc_mechanism::difc_function = difc_function_;
    return;
}

void
load_request_function(const std::function<std::vector<unsigned char>(const dmaabe::Attribute &)> & request_function_) {
    difc_mechanism::request_function = request_function_;
    return;
}

} // namespace rclcpp
#endif // _DIFC_MECHANISM_DIFC_HPP