#pragma once
#include <boost/asio.hpp>
#include <thread>
#include <iostream>
#include <string>
#include <mutex>

using boost::asio::ip::tcp;

class Client {
public:
    Client(boost::asio::io_service& io_service, const std::string& host, const std::string& port)
        : socket_(io_service), resolver_(io_service) {
        connect(host, port);
    }

    void write(const std::string& message) {
        boost::asio::write(socket_, boost::asio::buffer(message + "\n"));
    }

private:
    void connect(const std::string& host, const std::string& port) {
        tcp::resolver::query query(host, port);
        boost::asio::connect(socket_, resolver_.resolve(query));
    }

    tcp::socket socket_;
    tcp::resolver resolver_;
};


