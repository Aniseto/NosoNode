// NodeCpp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <thread>
#include <vector>
#include <mutex>
#include "Server.h"
#include "Client.h"
#include "Communications.h"

namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    try {
        // Define and parse the program options
        po::options_description desc("Allowed options"); //options_description is a class that describes a set of options.
        desc.add_options()
            ("help", "produce help message")
            ("port", po::value<int>()->default_value(8080), "set port number")
            ("testnet", po::bool_switch()->default_value(false), "use testnet");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            return 1;
        }

        int port = vm["port"].as<int>();
        bool testnet = vm["testnet"].as<bool>();

        std::cout << "Starting server on port " << port << "\n";
        if (testnet) {
            std::cout << "Testnet mode enabled\n";
        }

        boost::asio::io_service io_service;
        Server server(io_service, port);
        io_service.run();
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}




