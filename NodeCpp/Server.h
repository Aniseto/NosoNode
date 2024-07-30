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

#define DEFAULT_NODE_IPV4 "127.0.0.1"
#define DEFAULT_NODE_PORT 8080
#define DEFAULT_NODE_VERSION "0.4.2Da1"
#define DEFAULT_NODE_PROTOCOL 2
#define DEFAULT_BUFFER_SIZE 1024

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

        
        
        //Connect to a node, present and answer to PING using $PONG.
        // Connect to the destination server and send the NodePresentation
        boost::asio::io_service io_service;
        tcp::resolver resolver(io_service);
        //tcp::resolver::query query("38.242.253.13", "4040");
        tcp::resolver::query query("20.199.50.27", "8080");
        //tcp::resolver::query query("38.242.252.153", "4040");
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        auto socket = std::make_shared<tcp::socket>(io_service);
        boost::asio::connect(*socket, endpoint_iterator);

        //std::string testping = " $PING 1 0 4E8A4743AA6083F3833DDA1216FE3717 D41D8CD98F00B204E9800998ECF8427E 0 D41D8CD98F00B204E9800998ECF8427E %hu %hu D41D8 0 00000000000000000000000000000000 0 D41D8CD98F00B204E9800998ECF8427E D41D8\n";
        /*"$PING "                                // Magic string
            "1 "                                    // Current connections
            "0 "                                    // Block number
            "4E8A4743AA6083F3833DDA1216FE3717 "     // Block Hash (Genesis block hash)
            "D41D8CD98F00B204E9800998ECF8427E "     // Hash summary.psk (This is the MD5 hash for empty)
            "0 "                                    // Pending Orders
            "D41D8CD98F00B204E9800998ECF8427E "     // Hash blchhead.nos (This is the MD5 hash for empty)
            "%hu "                                  // Connections status [0=Disconnected,1=Connecting,2=Connected,3=Updated]
            "%hu "                                  // Node IP port
            "D41D8 "                                // Hash(5) masternodes.txt (This is the MD5 hash for empty)
            "0 "                                    // MNs Count
            "00000000000000000000000000000000 "     // NMsData diff/ Besthash diff
            "0 "                                    // Checked Master Nodes
            "D41D8CD98F00B204E9800998ECF8427E "     // Hash gvts.psk (This is the MD5 hash for empty)
            "D41D8\n",                              // Hash(5) CFGs
            g_node_protocol,
            g_node_version.c_str(),
            (long long)time(0),
            g_node_port,
            conn_status);*/
        std::string TestPING = " $PING 1 0 4E8A4743AA6083F3833DDA1216FE3717 D41D8CD98F00B204E9800998ECF8427E 0 D41D8CD98F00B204E9800998ECF8427E 0 8080 D41D8 0 00000000000000000000000000000000 0 D41D8CD98F00B204E9800998ECF8427E D41D8\n";
        std::string message = NodePresentation + "\n";
        std::string messagecompleted = NodePresentation + TestPING;

        std::cout << "Message Sent Hello ->  " << message; //<< std::endl;
        std::cout << "Message Sent PING ->  " << TestPING; //<< std::endl;
        //boost::asio::write(*socket, boost::asio::buffer(message)); //Send Hello
        //boost::asio::write(*socket, boost::asio::buffer(TestPING));
        //std::string messageSent = message + TestPING;
        std::cout << "Message Sent Comppleted ->  " << messagecompleted << std::endl;

        boost::asio::write(*socket, boost::asio::buffer(messagecompleted));
        try {
            for (;;) {
                boost::asio::streambuf buffer;
                boost::asio::read_until(*socket, buffer, "\n");
                std::istream is(&buffer);
                std::string message2;
                std::getline(is, message2);

                std::cout << "Received: " << message2 << std::endl;

                if (message2 == "$PING ") {
                    std::cout << "Reci " << message2 << std::endl;
                    boost::asio::write(*socket, boost::asio::buffer("$PONG\n"));
                }
                //else std::cout << "Reci "
            }
        }
        catch (std::exception& e) {
            std::cerr << "Exception in thread: " << e.what() << std::endl;
        }
        // Run the io_service to handle async operations
        io_service.run();

        // check LocalFIles, Download Blocks ( from vaild Node, and Checksum ) , Config .. etc

        

    }
    int send_ping(tcp::socket& socket, short conn_status) {
        //const std::size_t DEFAULT_BUFFER_SIZE = 1024;
        char buffer[DEFAULT_BUFFER_SIZE];
        std::size_t ping_size = std::snprintf(
            buffer, DEFAULT_BUFFER_SIZE - 1,
            "PSK %u %s %llu "
            "$PING "                                // Magic string
            "1 "                                    // Current connections
            "0 "                                    // Block number
            "4E8A4743AA6083F3833DDA1216FE3717 "     // Block Hash (Genesis block hash)
            "D41D8CD98F00B204E9800998ECF8427E "     // Hash summary.psk (This is the MD5 hash for empty)
            "0 "                                    // Pending Orders
            "D41D8CD98F00B204E9800998ECF8427E "     // Hash blchhead.nos (This is the MD5 hash for empty)
            "%hu "                                  // Connections status [0=Disconnected,1=Connecting,2=Connected,3=Updated]
            "%hu "                                  // Node IP port
            "D41D8 "                                // Hash(5) masternodes.txt (This is the MD5 hash for empty)
            "0 "                                    // MNs Count
            "00000000000000000000000000000000 "     // NMsData diff/ Besthash diff
            "0 "                                    // Checked Master Nodes
            "D41D8CD98F00B204E9800998ECF8427E "     // Hash gvts.psk (This is the MD5 hash for empty)
            "D41D8\n",                              // Hash(5) CFGs
            g_node_protocol,
            g_node_version.c_str(),
            static_cast<long long>(std::time(0)),
            g_node_port,
            conn_status);

        boost::system::error_code ec;
        boost::asio::write(socket, boost::asio::buffer(buffer, ping_size), ec);

        if (ec) {
            std::cerr << "Failed sending ping command: " << ec.message() << std::endl;
            return -1;
        }

        buffer[ping_size - 1] = '\0'; // Eliminate the newline char for output
        std::cout << " ---> " << buffer << std::endl;

        return 0;
    }
    /*static int
        send_pong(struct bufferevent* bev, short conn_status) {
        assert(bev);
        char buffer[DEFAULT_BUFFER_SIZE];
        std::size_t pong_size = std::snprintf(
            buffer, DEFAULT_BUFFER_SIZE - 1,
            "PSK %u %s %llu "
            "$PONG "                                // Magic string
            "0 "                                    // Current connections
            "0 "                                    // Block number
            "4E8A4743AA6083F3833DDA1216FE3717 "     // Block Hash (Genesis block hash)
            "D41D8CD98F00B204E9800998ECF8427E "     // Hash summary.psk (This is the MD5 hash for empty)
            "0 "                                    // Pending Orders
            "D41D8CD98F00B204E9800998ECF8427E "     // Hash blchhead.nos (This is the MD5 hash for empty)
            "%hu "                                    // Connections status [0=Disconnected,1=Connecting,2=Connected,3=Updated]
            "%hu "                                  // Node IP port
            "D41D8 "                                // Hash(5) masternodes.txt (This is the MD5 hash for empty)
            "0 "                                    // MNs Count
            "00000000000000000000000000000000 "     // NMsData diff/ Besthash diff
            "0 "                                    // Checked Master Nodes
            "D41D8CD98F00B204E9800998ECF8427E "     // Hash gvts.psk (This is the MD5 hash for empty)
            "D41D8\n",                              // Hash(5) CFGs
            g_node_protocol,
            g_node_version.c_str(),
            (long long)time(0),
            g_node_port,
            conn_status);
        if (bufferevent_write(bev, buffer, strlen(buffer)) < 0) {
            LOG("", "Failed sending pong command!");
            return -1;
        }
        buffer[pong_size - 1] = '\0'; // eliminate the newline char for output
        LOG(" ---> ", buffer);
        return 0;
    }
    
    */
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
                std::cout << message;

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
    std::string g_node_protocol = std::to_string(DEFAULT_NODE_PROTOCOL);
    std::string g_node_version = DEFAULT_NODE_VERSION;
    std::string g_node_port = std::to_string(DEFAULT_NODE_PORT);

};

