#pragma once
#include <boost/asio.hpp>
#include <thread>
#include <iostream>
#include <vector>
#include <mutex>
#include <sstream>
#include <chrono>
#include <fstream>
#include <string>
#include <cstdlib>
#include "Communications.h"

using boost::asio::ip::tcp;

class Server {

public:

    std::vector<std::string> ListSeedIpAddresses; 

    Server(boost::asio::io_service& io_service, short port)
        : acceptor_(io_service, tcp::endpoint(tcp::v4(), port)), socket_(io_service), timer_(io_service) {
        initialize(); // Check al files, configuration.... 
        start_accept();
    }
    void initialize() {
        std::cout << "Node initialitzation\n";
        std::vector<std::string> ListSeedIpAddresses = GetSeedIPAddresses();
        SaveToTextFile(ListSeedIpAddresses, "SeedIPAddresses.txt");
        std::cout << "Total Testnet Seed Nodes : " <<ListSeedIpAddresses.size() << std::endl;
        std::cout << "Seed IP Addresses:" << std::endl;
        for (const auto& ip : ListSeedIpAddresses) {
            std::cout << ip << std::endl;
        }
        std::cout << "Calculating Merkle Tree from Nodes: \n";
        std::string CurrentMerkle=CalculateMerkle(ListSeedIpAddresses);
        std::cout << "Valid Merkle : " << CurrentMerkle << std::endl;

        std::string NodePresentation = GetNodePresentation();
        std::cout << "Calculating Node Presentation String\n";
        std::cout << "Node Presentation String-> " << NodePresentation << std::endl;

        // check LocalFIles, Download Blocks ( from vaild Node, and Checksum ) , Config .. etc
        

    }
    std::string CalculateMerkle(std::vector<std::string> SeedIpAddresses)
    {
    	//Check SeedIpAddresses vector, for each item calculate md5.
        // Create a vector with all md5 hashes.
        // Calculate MerkleTree from all md5 hashes. Select the most common >50%
        //Execute each new Block
        //Create Node Class, IP, Port, ... etc. + Calculate Merckle function, getters, setters.
        //Create Node Vector with all seed nodes.
        //SeedIPAddressess is a vector with all púbic IP addresses of the seed nodes.
        //Step 1: Send to each node the command "$NODESTATUS\n" in order to get NODESTATUS string
        //step 2: Calculate MD5 to get MerkleTree
        //Step 3: Compare all merkletree calculated, and return the most "common" >50%.


        
        
        //Return: Valir MerckleTree for this block
        std::string merkleRoot = "test";
        return merkleRoot;
    }
    
    
    
    void SaveToTextFile(const std::vector<std::string>& ipAddresses, const std::string& filename) {
        std::ofstream outputFile(filename);
        if (!outputFile.is_open()) {
            std::cerr << "Error opening the file " << filename << " so save data" << std::endl;
            return;
        }

        //  Save each address to the file
        for (const auto& ip : ipAddresses) {
            outputFile << ip << std::endl;
        }

        outputFile.close();
    }

    std::vector<std::string> GetSeedIPAddresses() {
        std::string domain = "testnet.nosocoin.com";
        std::vector<std::string> ipAddresses;

        struct addrinfo hints, * res, * p;
        int status;

        // Setting the search criteria
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC; // AF_INET o AF_INET6 to force IPv4 o IPv6
        hints.ai_socktype = SOCK_STREAM;

        // Make DNS query
        if ((status = getaddrinfo(domain.c_str(), NULL, &hints, &res)) != 0) {
            std::cerr << "Error getting information: " << gai_strerror(status) << std::endl;
            return ipAddresses;
        }

        // Go to all results and get IP
        for (p = res; p != NULL; p = p->ai_next) {
            void* addr;
            std::string ipString;

            // Geting IPV4 address ir IPV6
            if (p->ai_family == AF_INET) { // IPv4
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                addr = &(ipv4->sin_addr);
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, addr, ip, sizeof(ip));
                ipString = ip;
            }
            else { // IPv6
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
                addr = &(ipv6->sin6_addr);
                char ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, addr, ip, sizeof(ip));
                ipString = ip;
            }

            // Add address to vector
            ipAddresses.push_back(ipString);
        }

        freeaddrinfo(res); // Free memory 
        //std::cout << "Seed Vector has #elements : " << ipAddresses.size() << std::endl;
        if (ipAddresses.size() == 0)
        {
            std::cerr << "Error getting IP addresses from " << domain << std::endl;
            std::cout << "Error loading seed ip, reading from SeedIPaddresses.txt file" << std::endl;
            ipAddresses = ReadSeedIPAddressesFromFile("SeedIPAddresses.txt");
        }

        return ipAddresses;
    }
    std::vector<std::string> ReadSeedIPAddressesFromFile(const std::string& filename) {
        std::vector<std::string> ipAddresses;
        std::ifstream inputFile(filename);
        if (!inputFile.is_open()) {
            std::cerr << "Error opening file" << filename << std::endl;
            //If file does not exist, return a default trusted seed nodes.
            ipAddresses.push_back("173.249.18.228");
            ipAddresses.push_back("38.242.252.153");
            return ipAddresses;
        }

        std::string line;
        while (std::getline(inputFile, line)) {
            ipAddresses.push_back(line);
        }

        inputFile.close();
        return ipAddresses;
    }

    void start_accept() {
        acceptor_.async_accept(socket_, [this](boost::system::error_code ec) {
            if (!ec) {
                std::thread(&Server::handle_client, this, std::move(socket_)).detach();
            }
            start_accept();
            });
    }


    
    std::string GetNodePublicIP() {
            
        CURL* curl;
        CURLcode res;
        std::string readBuffer;

        curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, "https://api.ipify.org");
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            }
            curl_easy_cleanup(curl);
        }

        return readBuffer;

    }
    std::string GetUTCTimeString(const std::string& ntpServer = "pool.ntp.org")
    {
        try
        {
            boost::asio::io_context io_context;
            boost::asio::ip::udp::resolver resolver(io_context);
            boost::asio::ip::udp::endpoint receiver_endpoint = *resolver.resolve(boost::asio::ip::udp::v4(), ntpServer, "ntp").begin();
            boost::asio::ip::udp::socket socket(io_context);
            socket.open(boost::asio::ip::udp::v4());

            // Formar la solicitud NTP
            std::array<uint8_t, 48> send_buf{ 0 };
            send_buf[0] = 0x1B;

            // Enviar la solicitud NTP
            socket.send_to(boost::asio::buffer(send_buf), receiver_endpoint);

            // Recibir la respuesta NTP
            std::array<uint8_t, 48> recv_buf;
            boost::asio::ip::udp::endpoint sender_endpoint;
            size_t len = socket.receive_from(boost::asio::buffer(recv_buf), sender_endpoint);

            if (len < 48)
            {
                throw std::runtime_error("Respuesta NTP incompleta");
            }

            // Analizar la respuesta NTP
            uint32_t seconds = (recv_buf[40] << 24) | (recv_buf[41] << 16) | (recv_buf[42] << 8) | recv_buf[43];
            uint64_t epoch = static_cast<uint64_t>(seconds) - 2208988800U; // Diferencia entre 1900-1970

            socket.close();

            return std::to_string(epoch);
        }
        catch (const std::exception& ex)
        {
            // Manejo básico de errores
            throw std::runtime_error(std::string("Error: ") + ex.what());
        }
    }

    std::string GetNodePresentation()
    {
        std::string UTCTime = Server::GetUTCTimeString();
        std::cout << "\nUTC Time: " << UTCTime << std::endl;
        std::cout << "\nProgramVersion: " << ProgramVersion << std::endl;
        std::cout << "\nSubversion: " << Subversion << std::endl;
        std::string NodePublicIP = GetNodePublicIP();
        std::cout << "\nNode Public IP: " << NodePublicIP << std::endl;
        std::string presentation = "PSK " + NodePublicIP + " " + ProgramVersion + Subversion + " " + UTCTime;
        std::cout << "\nNode Presentation: " << presentation << std::endl;
        return presentation;
    }

    void handle_client(tcp::socket socket) {
        try {
            for (;;) {
                boost::asio::streambuf buffer;
                boost::asio::read_until(socket, buffer, "\n");
                std::istream is(&buffer);
                std::string message;
                std::getline(is, message);

                //if (message == "exit") break;


                if (message == "$PING") {
                    std::cout << "$PING -> $PONG\n";
                    boost::asio::write(socket, boost::asio::buffer("$PONG\n"));
                }
                else {
                    std::lock_guard<std::mutex> lock(mutex_);
                    info = message;
                    std::cout << "Info updated to: " << info << std::endl;

                    // Set a timer to close the connection in 5 seconds if not $PING
                    timer_.expires_from_now(boost::posix_time::seconds(5));
                    timer_.async_wait([&socket](const boost::system::error_code& ec) {
                        if (!ec) {
                            std::cout << "Closing connection due to non-$PING valid message received lasts 5 seconds." << std::endl;
                            socket.close();
                        }
                        });

                    // Prevent the server from immediately continuing to the next read_until
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                }
            }
        }
        catch (std::exception& e) {
            std::cerr << "Exception in thread: " << e.what() << std::endl;
        }
    }

private:
    tcp::acceptor acceptor_;
    tcp::socket socket_;
    std::mutex mutex_;
    std::string info = "hola";
    boost::asio::deadline_timer timer_;
    //std::string MerckleTree;
    std::string ProgramVersion = "0.4.2";
    std::string Subversion = "Cb1";
};

