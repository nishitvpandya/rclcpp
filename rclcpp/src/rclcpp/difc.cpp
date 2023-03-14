#ifndef _DIFC_MECHANISM_DIFC_HPP
#define _DIFC_MECHANISM_DIFC_HPP

#include "dmaabe/comms/authority_user.hpp"
#include "dmaabe/comms/inter_authority.hpp"
#include "dmaabe/core/encryptor.hpp"
#include "dmaabe/core/decryptor.hpp"

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

#include <unistd.h>

#include <fstream>
#define CLOCK_RATE 3400UL

static inline uint64_t rdtsc()
{
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

namespace rclcpp
{

SerializedMessage difc_decrypt(
    const SerializedMessage & msg,
    const std::function<std::vector<unsigned char>(const std::string &)> data_function = [](const std::string & topic)
    {(void)topic; return std::vector<unsigned char>();}    
);

SerializedMessage difc_encrypt(
    const SerializedMessage & msg,
    const std::string & topic,
    const std::function<std::vector<unsigned char>(const std::string &)> data_function = [](const std::string & topic)
    {(void)topic; return std::vector<unsigned char>();} 
);

}

namespace difc_mechanism {

std::vector<std::string>
exec(const char * cmd)
    {
        std::array<char, 1024> buffer;
        std::vector<std::string> result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
        if (!pipe)
            {
                throw std::runtime_error("popen() failed.");
            }
        while(fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
            {
                result.push_back(buffer.data());
            }
        return result;
    }

template<class Data>
std::vector<unsigned char>
convert_to_vector(Data data)
    {
        std::stringstream output_data;
        cereal::PortableBinaryOutputArchive outar(output_data);
        data.serialize(outar);
        std::vector<unsigned char> vec;
        char ch;
        while(output_data.get(ch))
            vec.push_back((unsigned char)ch);
        return vec;
    }

template<class Data>
Data
convert_from_vector(std::vector<unsigned char> vec)
    {
        std::stringstream input_data;
        for(const auto & ch : vec)
            {
                input_data.put(ch);
            }
        cereal::PortableBinaryInputArchive inar(input_data);
        Data data_obj;
        data_obj.serialize(inar);
        return data_obj;
    }



struct SentKey {
    dmaabe::UserKey dec_key;
    dmaabe::UserEncryptionKey enc_key;
    bool allow_declassify;
    size_t pid;

    template<class Archive>
    void
    serialize(Archive & ar)
        {
            ar(dec_key, enc_key, allow_declassify, pid);
        }
};

struct SignedSentKey {
    std::vector<unsigned char> sent_key;
    std::string signature;

    template<class Archive>
    void
    serialize(Archive & ar)
        {
            ar(sent_key, signature);
        }
};

struct DeserRequest {
    size_t pid;
    std::string topic;
    std::vector<unsigned char> metadata;

    template<class Archive>
    void
    serialize(Archive & ar)
        {
            ar(pid, topic, metadata);
        }

};

std::string
load_public_coin(const std::string & public_coin_file_path = "/home/nishit/ros2_humble/src/ros2/difc_ros2/difc_test/first_tests/test_metadata/public_coin.txt")
    {
        std::ifstream public_coin_file_handle(public_coin_file_path);
        std::stringstream pub_coin_str;
        pub_coin_str << public_coin_file_handle.rdbuf();
        return pub_coin_str.str();
    }

class ProcessDIFCManager {

    private:
        static void* memory_location;
        static void lkm_memory_init()
            {
                constexpr const size_t MEMORY_SIZE = 1000000;
                memory_location = mmap(NULL, MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
                if(memory_location == MAP_FAILED)
                    throw std::exception();
            }

        static   
        void
        report_to_os(const std::vector<unsigned char> & signed_key)
        {
            // Take the const std::vector & signed_key, send it to the verification daemon as follows.
            // 1. The verification daemon is a ROS2 service with name "/verifier" or something like that.
            // You can choose the name as you wish as long as it is the same everywhere.
            // 2. The signed_key parameter passed to this function will be sent as the body of the request
            // 3. The request code can be anything you want as long as it matches on both sides.
            // 
            // On the /verifier daemon, the verifier will receive the signed_key in the body of the request,
            // then deserialize it using the convert_from_vector function (defined above) into a SignedSentKey
            // (also defined above).
            // It will verify the signature of the SignedSentKey (.signature)
            // If the signature verifies correctly, it will deserialize the .sent_key field using the convert_from_vector
            // function again into a SentKey (defined above)
            // It will then look at the SentKey::declassify field obtained above and if the bool is true, it will
            // do nothing.
            // If the bool is false, it will look at the SentKey::enc_key, serialize it into a vector of unsigned char/
            // string and paste it into the address space of the pid mentioned in the SentKey::pid field.
            // 
            auto signed_sent_key = convert_from_vector<SignedSentKey>(signed_key);
            auto sent_key = convert_from_vector<SentKey>(signed_sent_key.sent_key);

            for(const auto & [attr, small_enc_key] : sent_key.enc_key.data)
                {
                    auto vectorized_key = convert_to_vector(small_enc_key);
                    std::string stringed_v(vectorized_key.begin(), vectorized_key.end());
                    {
                        std::lock_guard<std::mutex> enc_mtx_lock(enc_mtx);
                        encryptor.load_os_key(stringed_v);
                    }
                    std::cout << "New report to OS." << std::endl;
                }
        }
 
    public:
        static std::string enclave_name;
        static std::unordered_map<std::string, bool> write_permissions;
        static std::unordered_map<std::string, bool> read_permissions;
        static std::unordered_map<std::string, dmaabe::UserEncryptionKey> own_encryption_keys;
        static dmaabe::Encryptor encryptor;
        static std::mutex enc_mtx;
        static dmaabe::Decryptor decryptor;
        static std::mutex dec_mtx;
        static std::string self_difc_controller_name;

        static void process_difc_manager_init(const std::string & public_coin, const std::string & enclave_name_ = std::string())
            {
                auto pid_str = std::to_string(getpid());
                mcl::bn::G1 g1;
                mcl::bn::G2 g2;
                mcl::bn::hashAndMapToG1(g1, public_coin);
                mcl::bn::hashAndMapToG2(g2, public_coin);
                encryptor.load_generators(g1, g2);
                enclave_name = enclave_name_;
                if(!enclave_name.empty())
                {
                    sleep(5);
                    auto running_difc_controllers = exec(std::string("ros2 service list | grep " + enclave_name + "_difccontroller").c_str());
                    if(running_difc_controllers.empty())
                    {
                        // std::cout << "No DIFC Controller found" << std::endl;
                    }
                }
                // std::cout << "Empty Enclave Name." << std::endl;
                lkm_memory_init();
                encryptor.load_lkm_memory_location(memory_location);
            }

        dmaabe::Ciphertext
        difc_encrypt(
            const rclcpp::SerializedMessage & message, 
            const std::string & topic,
            const std::function<std::vector<unsigned char>(const std::string &)> data_function
        )
        {
            auto & rcl_handle = message.get_rcl_serialized_message();
            std::vector<unsigned char> vec_message;
            vec_message.reserve(rcl_handle.buffer_length);
            for(size_t len = 0; len < rcl_handle.buffer_length; ++len)
                vec_message.push_back((unsigned char)*(rcl_handle.buffer + len));
            
            dmaabe::Ciphertext encrypted;
            if(enclave_name.empty()) {
                // std::cout << "Enclave Name is empty. Encrypting from OS" << std::endl;
                // uint64_t start_time, end_time;
                // start_time = rdtsc();
                
                encrypted = encryptor.encrypt_from_os(encryptor.encode(vec_message));
                
                // end_time = rdtsc();
                // uint64_t cycles = end_time - start_time;
                // double microseconds = (double)cycles / CLOCK_RATE;

                // std::ofstream logFile;
                // logFile.open("/home/nishit/ros2_humble/encrypt_from_os.txt",std::ios::app);
                // logFile << cycles << ", Time micro-sec: ";
                // logFile << microseconds << std::endl;
                // logFile.close();
            }
            else {
                if(write_permissions.find(topic) == write_permissions.end())
                {
                    // std::cout << "Permission not found. Requesting" << std::endl;
                    auto pid_str = std::to_string(getpid());
                    auto difc_comms_node = std::make_shared<rclcpp::Node>("pid_" + pid_str + "_difcrequester");
                    auto permissions_client = difc_comms_node.get() -> create_client<difc_interfaces::srv::DIFCRequest>("/" + enclave_name + "_p2plistener");
                    const auto req_first_step = std::make_shared<difc_interfaces::srv::DIFCRequest::Request>();
                    req_first_step -> req_type = 0x02;
                    req_first_step -> request = convert_to_vector<DeserRequest>(
                        {
                            .pid = getpid(),
                            .topic = topic,
                            .metadata = data_function(topic)
                        }
                    );

                    auto future_result = permissions_client -> async_send_request(req_first_step);
                    if (rclcpp::spin_until_future_complete(difc_comms_node, future_result) == rclcpp::FutureReturnCode::SUCCESS)
                        {
                            auto res = future_result.get();
                            if(res -> response_status == 0)
                                {
                                    // std::cout << "Permission Received." << std::endl;
                                    report_to_os(res -> response);
                                    auto signed_key = convert_from_vector<SignedSentKey>(res -> response);
                                    auto sent_key = convert_from_vector<SentKey>(signed_key.sent_key);
                                    {
                                        std::lock_guard<std::mutex> enc_mtx_grd(enc_mtx);
                                        for(const auto & [att, small_enc_key] : sent_key.enc_key.data)
                                            encryptor.load_enc_key(att, small_enc_key);
                                        write_permissions[topic] = true;
                                    }
                                    // std::cout << "Write permission updated?" << std::endl;
                                    {
                                        std::lock_guard<std::mutex> dec_mtx_grd(dec_mtx);
                                        for(const auto & [guid, small_dec_key] : sent_key.dec_key.key)
                                            decryptor.load_key_from(guid, small_dec_key);
                                        for(const auto & [attr, small_enc_key] : sent_key.enc_key.data)
                                            {
                                                read_permissions[small_enc_key.guids_for_attrs.first] = true;
                                                read_permissions[small_enc_key.guids_for_attrs.second] = true;
                                            }
                                    }
                                    // std::cout << "State Updated?" << std::endl;
                                }
                            else
                                {
                                    write_permissions[topic] = false;
                                    read_permissions[topic] = false;
                                }
                        }

                }
                
                if(write_permissions[topic]) {
                    
                    // uint64_t start_time, end_time;
                    // start_time = rdtsc();
                    encrypted = encryptor.encrypt_from_os_and_self(encryptor.encode(vec_message), enclave_name + "." + topic);
                    
                    // end_time = rdtsc();
                    // uint64_t cycles = end_time - start_time;
                    // double microseconds = (double)cycles / CLOCK_RATE;

                    // std::ofstream logFile;
                    // logFile.open("/home/nishit/ros2_humble/encrypt_from_os_and_self.txt",std::ios::app);
                    // logFile << cycles << ", Time micro-sec: ";
                    // logFile << microseconds << std::endl;
                    // logFile.close();
                    
                }
            }
            return encrypted;
        }

        std::vector<unsigned char>
        difc_decrypt(
            const dmaabe::Ciphertext & cipher,
            const std::function<std::vector<unsigned char>(const std::string &)> data_function
        )
        {
            // std::cout << "Innermost decrypt called." << std::endl;
            std::unordered_map<std::string, std::vector<std::string>> requests_guid;
            for(const auto & [guid, att_term] : cipher.ser_att_terms)
                {
                    if(read_permissions.find(guid) == read_permissions.end())
                        {
                            std::stringstream temp_str(guid);
                            std::string req_enc_name;
                            std::getline(temp_str, req_enc_name, '.');
                            requests_guid[req_enc_name].push_back(guid);
                        }
                }
            
            for(const auto & [enclave, att_term] : requests_guid)
                {
                    dmaabe::UserKeyRequest req = {
                        .requester_guid = std::to_string(getpid()),
                        .requested_guids = att_term
                    };
                    auto req_vec = convert_to_vector(req);
                    auto pid_str = std::to_string(getpid());
                    auto difc_comms_node = std::make_shared<rclcpp::Node>("pid_" + pid_str + "_difcrequester");
                    auto permissions_client = difc_comms_node.get() -> create_client<difc_interfaces::srv::DIFCRequest>("/" + enclave + "_p2plistener");
                    const auto req_first_step = std::make_shared<difc_interfaces::srv::DIFCRequest::Request>();
                    req_first_step -> req_type = 0x03;
                    req_first_step -> request = req_vec;
                    auto future_result = permissions_client -> async_send_request(req_first_step);
                    if (rclcpp::spin_until_future_complete(difc_comms_node, future_result) == rclcpp::FutureReturnCode::SUCCESS)
                        {
                            auto res = future_result.get();
                            if(res -> response_status == 0)
                                {
                                    auto signed_key = convert_from_vector<SignedSentKey>(res -> response);
                                    auto sent_key = convert_from_vector<SentKey>(signed_key.sent_key);
                                    {
                                        std::lock_guard<std::mutex> enc_mtx_grd(enc_mtx);
                                        for(const auto & [att, small_enc_key] : sent_key.enc_key.data)
                                            encryptor.load_enc_key(att, small_enc_key);
                                    }
                                    {
                                        std::lock_guard<std::mutex> dec_mtx_grd(dec_mtx);
                                        for(const auto & [guid, small_dec_key] : sent_key.dec_key.key)
                                            decryptor.load_key_from(guid, small_dec_key);
                                        for(const auto & [attr, small_enc_key] : sent_key.enc_key.data)
                                            {
                                                read_permissions[small_enc_key.guids_for_attrs.first] = true;
                                                read_permissions[small_enc_key.guids_for_attrs.second] = true;
                                            }
                                    }
                                }
                            else
                                {
                                    for(const auto & att : att_term)
                                        read_permissions[att] = false;
                                }
                        }

                }
            
            bool all_permits = true;
            for(const auto & [guid, att_term] : cipher.ser_att_terms)
            {
                all_permits &= read_permissions[guid];
            }

            if(all_permits) {
                auto plaintext_messages = decryptor.decrypt(cipher);
                return decryptor.decode(plaintext_messages);
            }
            return std::vector<unsigned char>();

        }

};
}

using difc_mechanism::ProcessDIFCManager;
std::string ProcessDIFCManager::enclave_name = std::string();
std::unordered_map<std::string, bool> ProcessDIFCManager::write_permissions = std::unordered_map<std::string, bool>();
std::unordered_map<std::string, bool> ProcessDIFCManager::read_permissions = std::unordered_map<std::string, bool>();
std::unordered_map<std::string, dmaabe::UserEncryptionKey> ProcessDIFCManager::own_encryption_keys = std::unordered_map<std::string, dmaabe::UserEncryptionKey>();
dmaabe::Encryptor ProcessDIFCManager::encryptor = dmaabe::Encryptor();
std::mutex ProcessDIFCManager::enc_mtx = std::mutex();
dmaabe::Decryptor ProcessDIFCManager::decryptor;
std::mutex ProcessDIFCManager::dec_mtx;
// std::shared_ptr<rclcpp::Node> ProcessDIFCManager::difc_comms_node;
void* ProcessDIFCManager::memory_location = nullptr;

ProcessDIFCManager process_manager;

namespace rclcpp{

void difc_init(const std::string & enclave_name_)
    {
        std::cout << "DIFC Library called." << std::endl;
        std::string public_coin = difc_mechanism::load_public_coin();
        using difc_mechanism::ProcessDIFCManager;
        ProcessDIFCManager::process_difc_manager_init(public_coin, enclave_name_);
    }

SerializedMessage
difc_encrypt(
    const rclcpp::SerializedMessage & plaintext,
    const std::string & topic_name,
    const std::function<std::vector<unsigned char>(const std::string &)> data_function
)
{
    // std::cout << "Plaintext Message: " << plaintext.get_rcl_serialized_message().buffer << std::endl;
    // std::cout << "Plaintext Size: " << plaintext.size() << std::endl;
    
    // uint64_t start_time, end_time;
    // start_time = rdtsc();
    
    auto cipher = process_manager.difc_encrypt(plaintext, topic_name, data_function);

    // end_time = rdtsc();
    
    // uint64_t cycles = end_time - start_time;
    // double microseconds = (double)cycles / CLOCK_RATE;

    // std::ofstream logFile;
    // logFile.open("/home/nishit/ros2_humble/difc_encrypt.txt",std::ios::app);
    // logFile << cycles << ", Time micro-sec: ";
    // logFile << microseconds << std::endl;
    // logFile.close();
    
    // std::cout << "Encrypted message: " << cipher.serialized_message_terms[0] << std::endl;
    // std::cout << "Outside E1: " << cipher.ser_E1 << std::endl;
    auto vectorized_cipher = difc_mechanism::convert_to_vector<dmaabe::Ciphertext>(cipher);
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
}


SerializedMessage
difc_decrypt(
        const rclcpp::SerializedMessage & ciphertext,
        const std::function<std::vector<unsigned char>(const std::string &)> data_function
)
{
    const auto & rcl_handle = ciphertext.get_rcl_serialized_message();
    std::vector<unsigned char> cipher_vec;
    // std::cout << "Buffer received: " << rcl_handle.buffer_length << std::endl;
    cipher_vec.reserve(rcl_handle.buffer_length - 3);
    for(size_t i = 0; i < rcl_handle.buffer_length - 3; ++i)
        cipher_vec.push_back(rcl_handle.buffer[i]);
    if(rcl_handle.buffer[rcl_handle.buffer_length -2] == '\0');
        // std::cout << "Check passed." << std::endl;
    // std::cout << "Vector Written of size " << cipher_vec.size() << std::endl;
    auto cipher = difc_mechanism::convert_from_vector<dmaabe::Ciphertext>(cipher_vec);
    auto plaintext = process_manager.difc_decrypt(cipher, data_function);
    std::string temp_str(plaintext.begin(), plaintext.end());
    rclcpp::SerializedMessage decrypted(temp_str.size() + 1);
    auto & rcl_handle_2 = decrypted.get_rcl_serialized_message();
    std::memcpy(rcl_handle_2.buffer, temp_str.c_str(), temp_str.size());
    rcl_handle_2.buffer[temp_str.size()] = '\0';
    rcl_handle_2.buffer_length = temp_str.size() + 1;
    return decrypted;
}

} // namespace rclcpp
#endif // _DIFC_MECHANISM_DIFC_HPP