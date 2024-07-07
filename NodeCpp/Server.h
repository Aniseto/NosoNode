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

using boost::asio::ip::tcp;

class Server {

public:

    Server(boost::asio::io_service& io_service, short port)
        : acceptor_(io_service, tcp::endpoint(tcp::v4(), port)), socket_(io_service), timer_(io_service) {
        initialize();
        start_accept(); //Test.
    }
    void initialize() {
        std::cout << "Node initialitzation\n";
        std::vector<std::string> SeedIpAddresses = GetSeedIPAddresses();
        SaveToTextFile(SeedIpAddresses, "SeedIPAddresses.txt");
        std::cout << "Total Seed Nodes : " << SeedIpAddresses.size() << std::endl;

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
            ipAddresses.push_back("20.199.50.27");
            ipAddresses.push_back("4.233.61.8");
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

    void handle_client(tcp::socket socket) {
        try {
            for (;;) {
                boost::asio::streambuf buffer;
                boost::asio::read_until(socket, buffer, "\n");
                std::istream is(&buffer);
                std::string message;
                std::getline(is, message);

                if (message == "exit") break;

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
};

