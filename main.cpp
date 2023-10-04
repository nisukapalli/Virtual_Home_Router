#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <vector>
#include <map>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define SERVER_PORT 5152
#define BUFFER_SIZE 65536
#define MAXCLIENTS 10
using namespace std;

void processInput(string& lanIP, string& wanIP, vector<string>& links, map<string, string>& portMap);
void displayServerInfo(string& lanIP, string& wanIP, vector<string>& links, map<string, string>& portMap);
void processIPPacketInfo(uint8_t* buffer, string& sourceIP, string& destinationIP, string& sourcePort, string& destinationPort, string& protocol, int& ipHeaderLength, int& timeToLive, uint16_t& ipChecksum, int& offset);
void processUDPPacket(uint8_t* buffer, int& packetLength, uint16_t& checksumValue, int offset);
void processTCPPacket(uint8_t* buffer, uint16_t& checksumValue, int offset);
bool modifyPacketInformation(uint8_t* newPacket, string& sourceIP, string& destinationIP, string& sourcePort, string& destinationPort, int ipHeaderLength, int& timeToLive, uint16_t& ipChecksum, 
                                string lanIP, string wanIP, vector<string>& links, map<string, string>& portMap, int& firstAllocablePortN, int offset);

void printHexValues(const uint8_t buffer[], int size);
void printCharArrValues(unsigned char* charArray, int size);
void ipAndPortToHex(string IP, string port, uint8_t* ipBuffer, uint8_t* portBuffer);
void modifyPacketIPandPort(uint8_t* packet, uint8_t ipBuff[], uint8_t portBuff[], string code, int offset);
void modifyPacketChecksum(uint8_t* packet, uint16_t checksumValue, string protocol, int offset);
void createChecksumPacket(uint8_t buffer[], uint8_t* checksumBuffer, int length, int offset);
void createIPChecksumPacket(uint8_t buffer[], uint8_t* checksumBuffer, int offset);
void extractLANandIP(string entry, string& lan, string& ip);
string extractPrefix(string IP);
uint16_t computeChecksum(uint8_t packet[], int lenPacket);

int main() {
    // Process input into:
    // Lan IP: szLanIp
    // Wan IP: szWanIp
    // Links: linksVector
    // NAT Table Mappings: portMappings
    string szLanIp;
    string szWanIp;
    vector<string> linksVector;
    map<string, string> portMappings;

    // Process the input
    processInput(szLanIp, szWanIp, linksVector, portMappings);

    // Display Server information
    displayServerInfo(szLanIp, szWanIp, linksVector, portMappings);

    // Assign the max number of allowed connections
    int maxConnections = linksVector.size();

    // PART 1: open up listening socket, multiplex with select()
    // Open up a bound and listening socket on TCP port 5152
    int optVal = 1;
    int serverSocket, newSocket, clientSockets[MAXCLIENTS], sd, maxsd;
    int activity;
    fd_set readfds;
    vector<int> newClientSockets;

    // Initialize the client socket fd references
    for (int i = 0; i < MAXCLIENTS; i++) {
        clientSockets[i] = 0;
    }

    // Initialize the socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal));
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(SERVER_PORT);
    memset(serverAddress.sin_zero, '\0', sizeof(serverAddress.sin_zero));

    if (bind(serverSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
      throw runtime_error("ERROR: bind faild.");
    }
    if (listen(serverSocket, 100) == -1) {
      throw runtime_error("ERROR: listen faild.");
    }
    
    cout << "Server socketed on " << SERVER_PORT << ", address " << szLanIp<< ". Awaiting connections... (Max: " << maxConnections << ")" << endl; 

    int nConnections = 0;
    int firstAllocablePort = 49152;


    while (1) {
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);
        maxsd = serverSocket;

        // Include connected sockets inside FD set
        for (int i = 0; i < MAXCLIENTS; i++) {
            sd = clientSockets[i];
            if (sd > 0) {
                FD_SET(sd, &readfds);
            }
            if (sd > maxsd) {
                maxsd = sd;
            }
        }

        // Use select to detect when a read event occurs
        activity = select(maxsd + 1, &readfds, NULL, NULL, NULL);
        if ((activity < 0) && (errno != EINTR)) {
            perror("select");
        }
        
        // Loop for accepting connections
        if (FD_ISSET(serverSocket, &readfds)) {
            sockaddr_in clientAddress{};
            socklen_t clientAddressLength = sizeof(clientAddress);
            int currentLink;
            nConnections += 1;

            // If number of connections exceeds the current number of links
            if (nConnections > maxConnections) {
                std::cout << "Connection rejected, maximum number of connections exceeded" << endl;
                continue;
                nConnections -= 1;
            }

            // Accept the connection
            newSocket = accept(serverSocket, reinterpret_cast<sockaddr*>(&clientAddress), &clientAddressLength);
            // cout << " connection " << newSocket << endl; 
            if (newSocket < 0) {
                throw runtime_error("ERROR: accept faild.");
            }

            cout << endl;
            printf("Client connected, ip: %s, port: %d\n", inet_ntoa(clientAddress.sin_addr), ntohs(clientAddress.sin_port));

            // Assign socket to socket array
            for (int i = 0; i < MAXCLIENTS; i++) {
                if (clientSockets[i] == 0) {
                    currentLink = i;
                    clientSockets[i] = newSocket;
                    newClientSockets.push_back(newSocket);                    
                    break;
                }
            } 

            // Print out the link assigned to the vector
            // CHECK: might be wrong: probably not able to make the assumption that connections are made in order of WAN, etc. etc..
            string socketIP = linksVector[currentLink];
            cout << "Client assigned link " << socketIP << ". Socket port: " << currentLink << endl;
            
            /*
            if (nConnections - 1 == 1) {
                uint8_t bs[28] = {0x45, 0x00, 0x00, 0x1c, 0x00, 0x00 , 0x40 , 0x00  , 0x3f , 0x11 , 0xe3 , 0xad , 0x62 , 0x95 , 0xeb , 0x84 , 0x0a , 0x00 , 0x00 , 0x0a , 0x1f , 0x90 , 0xc3 , 0x50  , 0x00 , 0x08 , 0xc4 , 0xd9};
                cout << "Sending bs to connection on port " << nConnections - 1 << endl;
                cout << "Data: " << endl;
                printHexValues(bs, 28);
                cout << endl;
                if (write(clientSockets[nConnections - 1], bs, 28) > 1) {
                    cout << "Bs sent!" << endl;
                }
                cout << "on port " << nConnections - 1 << endl;
            }
            */            
        }

        // Receive data from packet
        if (nConnections == maxConnections) {
            for (int i = 0; i < MAXCLIENTS; i++) {
                sd = clientSockets[i];
                uint8_t buffer[BUFFER_SIZE];
                int len;

                // Read packet data into a buffer
                if (sd > 0 && FD_ISSET(sd, &readfds)) {
                    int valread = read(sd, buffer, BUFFER_SIZE);
                    buffer[valread] = '\0';
                    len = valread; // Assign length
                    // If no more data to be sent, close the socket.
                    if (valread == 0) {
                        continue;
                    }
                    // Otherwise... validate and change the IP packet
                    else {
                        cout << "Packet Received!" << endl;
                        // Print out and load all of the relevant portions of the IP Header (TODO: Load Checksum)
                        printHexValues(buffer, valread);
                        cout << endl;
                        string srcIP, destIP, srcPort, destPort, proto;
                        int ipHeaderLen, TTL;
                        int offset;
                        uint16_t ipChecksumVal;
                        processIPPacketInfo(buffer, srcIP, destIP, srcPort, destPort, proto, ipHeaderLen, TTL, ipChecksumVal, offset);
                        //cout << "TTL:" << to_string(TTL) << endl;

                        // Drop if TTL == 0 or 1
                        if (TTL < 2) {
                            // dropPacket (TODO)
                            continue;
                        }

                        // Make a copy of the packet
                        //cout << "length: " << len << endl;
                        uint8_t packet[len];
                        copy(buffer, buffer + len, packet);
                        
                        // Compute checksum of IP Header; see if it matches.
                        uint8_t ipChecksumHeader[20 + offset];
                        createIPChecksumPacket(buffer, ipChecksumHeader, offset);
                        uint16_t ipChecksumComputedVal = computeChecksum(ipChecksumHeader, 20 + offset);
                        cout << "Listed Checksum: " << ipChecksumVal << " Calculated Checksum: " << ipChecksumComputedVal << endl;
                        if (ipChecksumComputedVal != ipChecksumVal) {
                            cout << "Dropped due to IP checksums not matching" << endl;
                            //drop()
                            continue;
                        }
                        
                        // Compute checksumHeader of given IP header
                        uint8_t checksumHeader[12 + len - 20 - offset]; // Psuedoheader = 12 + len, rest of everything is packet size - ip header length
                        cout << "Checksumheader length: " << to_string(12 + len - 20 - offset) << endl;
                        createChecksumPacket(packet, checksumHeader, len, offset);
                        cout << "Pre UDP checksumming:" << endl;
                        printHexValues(checksumHeader, 12 + len - 20 - offset);
                        cout << endl;

                        // If UDP:
                        if (proto == "UDP") {
                            int udpPacketLength;
                            uint16_t udpChecksumVal;

                            // Process relevant portions of UDP Header
                            processUDPPacket(buffer, udpPacketLength, udpChecksumVal, offset);

                            // Set relevant bytes of UDP Checksum Packet to 0
                            // offset is 7 bytes from end of psuedoheader index 11
                            checksumHeader[18] = 0x0;
                            checksumHeader[19] = 0x0;

                            cout << "Pre computation header: " << endl;
                            printHexValues(checksumHeader, 12 + len - 20 - offset); 
                            cout << endl;

                            // Compute UDP Checksum
                            uint16_t checksumValCalculated = computeChecksum(checksumHeader, 12 + len - 20 - offset);
                            cout << "UDP CHECKSUM VAL IN HEADER: " << udpChecksumVal << endl;
                            cout << "UDP CHECKSUM CALCULATED: " << checksumValCalculated << endl;

                            // Drop packet if checksum/length is incorrect.
                            if (checksumValCalculated != udpChecksumVal) {
                                // cout << "Packet dropped due to UDP checksum mismatch" << endl;
                                // drop()
                                continue;
                            }
                        }

                        // If TCP
                        else if (proto == "TCP") {
                            uint16_t tcpChecksumVal;
                            
                            // Process relevant portions of the TCP Header
                            processTCPPacket(buffer, tcpChecksumVal, offset);

                            // Set relevant bytes of TCP Checksum Packet to 0
                            // offset is 17 bytes from end of psuedoheader index 11
                            checksumHeader[28] = 0x0;
                            checksumHeader[29] = 0x0;

                            // Compute TCP Checksum
                            uint16_t checksumValCalculated = computeChecksum(checksumHeader, 12 + len - 20 - offset);

                            // Drop packet if checksum/length is incorrect.
                            if (checksumValCalculated != tcpChecksumVal) {
                                /// cout << "Packet dropped due to UDP checksum mismatch" << endl;
                                // drop()
                                continue;
                            }
                        }

                        bool toForward = modifyPacketInformation(packet, srcIP, destIP, srcPort, destPort, ipHeaderLen, TTL, ipChecksumVal, szLanIp, szWanIp, linksVector, portMappings, firstAllocablePort, offset);
                        uint8_t newChecksumPacket[12 + len - 20];
                        if (proto == "UDP" && toForward) {
                            // Recompute UDP Checksum; rewrite it to the packet.
                            createChecksumPacket(packet, newChecksumPacket, len, offset);
                            newChecksumPacket[18] = 0x0;
                            newChecksumPacket[19] = 0x0;
                            uint16_t newChecksumValCalculated = computeChecksum(newChecksumPacket, 12 + len - 20 - offset);
                            modifyPacketChecksum(packet, newChecksumValCalculated, "UDP", offset);
                        }
                        else if (proto == "TCP" && toForward){
                            // Recompute TCP Checksum; rewrite it to the packet.
                            createChecksumPacket(packet, newChecksumPacket, len, offset);
                            newChecksumPacket[28] = 0x0;
                            newChecksumPacket[29] = 0x0;
                            uint16_t newChecksumValCalculated = computeChecksum(newChecksumPacket, 12 + len - 20 - offset);
                            modifyPacketChecksum(packet, newChecksumValCalculated, "TCP", offset);
                        }

                        cout << "IP Packet Preforward:" << endl;
                        printHexValues(packet, len);
                        cout << endl;
                        cout << "Destination: " << destIP << endl;
                        // Forward to destination port
                        if (toForward) {
                            int iterator = 0;
                            int linkToForward = 0;
                            for (const string& str : linksVector) {
                                if (str == destIP) {
                                    linkToForward = iterator;
                                    break;
                                }
                                iterator += 1;
                            }
                            cout << "Link to forward to: " << linkToForward << endl;        
                            
                            int sentPacket = write(newClientSockets[linkToForward], packet, len);
                            if (sentPacket > 0) {
                                cout << "Packet sent to FD# " << clientSockets[linkToForward] << "corresponding to port " << linkToForward << endl;
                            }
                        }
                        else {
                            // drop() if toForward is false
                            continue;
                        }
                    }
                }
            }
        }
    }
    return 0;
}


// Function for Processing input
void processInput(string& lanIP, string& wanIP, vector<string>& links, map<string, string>& portMap) {
    string szLine;
    bool emptyLineReached = 0;
    while (getline(cin, szLine)) {
        // If the line is empty
        if (szLine.empty()) {
            // If it is the first occurence of an empty line, move on.
            if (!emptyLineReached) {
                emptyLineReached = 1;
            } else { break; }           
        }
        // Grab the first line with LAN address and WAN addresses
        else if (lanIP == "") {
            size_t dwPos = szLine.find(' ');
            lanIP = szLine.substr(0, dwPos);
            wanIP = szLine.substr(dwPos + 1);
        }
        else if (!emptyLineReached) {
            links.push_back(szLine);
        }
        // If we're past the first empty line, start mapping the ports
        else {
            string ip;
            string LANPort, WANPort;
            istringstream iss(szLine);
            if (!(iss >> ip >> LANPort >> WANPort)) {
                continue;
            }
            string combinedString = ip + ":" + LANPort;
            cout << combinedString << endl;
            portMap[combinedString] = WANPort;
            cout << portMap[combinedString] << endl;
        }
    }
}

// Display server information
void displayServerInfo(string& lanIP, string& wanIP, vector<string>& links, map<string, string>& portMap) {
    cout << endl;
    cout << "Server's LAN IP: " << lanIP << endl
         << "Server's WAN IP: " << wanIP << endl
         << "Links available: " << endl;
    for (const auto& link : links) {
        cout << link << " ";
    }
    cout << endl; 
    cout << "Nat port mappings: " << endl;
    for (const auto& entry : portMap) {
        string LAN, IP;
        extractLANandIP(entry.first, LAN, IP);
        const string& wanPort = entry.second;
        cout << IP << " -> " << LAN << ":" << wanPort << endl;
    }
    cout << endl;
}

void extractLANandIP(string entry, string& lan, string& ip) {
    bool colonFound = 0;
    string LAN = "";
    string IP = "";
    for (char c : entry) {
        if (c == ':') {
            colonFound = 1;
            continue;
        }
        else if (colonFound == 0) {
            IP += c;
        }
        else {
            LAN += c;
        }
    }
    lan = LAN;
    ip = IP;
}

// Load IP packet info into variables
void processIPPacketInfo(uint8_t* buffer, string& sourceIP, string& destinationIP, string& sourcePort, string& destinationPort, string& protocol, int& ipHeaderLength, int& timeToLive, uint16_t& ipChecksum, int& offset) {
    // Assign variables corresponding to the regions of the IP header
    uint8_t sourceIPHex[4] = {buffer[12], buffer[13], buffer[14], buffer[15]};
    uint8_t destIPHex[4] = {buffer[16], buffer[17], buffer[18], buffer[19]};
    uint8_t protocolHex = buffer[9];
    uint8_t headerLenHex[2] = {buffer[2], buffer[3]};
    uint8_t timeToLiveHex = buffer[8];
    uint8_t checksumHex[2] = {buffer[10], buffer[11]};
    uint16_t headerLenInt = static_cast<uint16_t>((headerLenHex[0] << 8) | headerLenHex[1]);
    int IHL = (buffer[0] & (0xF0) >> 4);
    offset = IHL * 4 - 20;
    ipChecksum = static_cast<uint16_t>((checksumHex[0] << 8) | checksumHex[1]);

    uint8_t sourcePortHex[2] = {buffer[20 + offset], buffer[21 + offset]};
    uint8_t destPortHex[2] = {buffer[22 + offset], buffer[23 + offset]};
    // Convert two byte integers into integers
    uint16_t sourcePortInt = static_cast<uint16_t>((sourcePortHex[0] << 8) | sourcePortHex[1]);
    uint16_t destPortInt = static_cast<uint16_t>((destPortHex[0] << 8) | destPortHex[1]);


    // Cast buffer into nonHex formats
    sourceIP = to_string(static_cast<int>(sourceIPHex[0])) + "." + to_string(static_cast<int>(sourceIPHex[1])) + "." + to_string(static_cast<int>(sourceIPHex[2])) + "." + to_string(static_cast<int>(sourceIPHex[3]));
    destinationIP = to_string(static_cast<int>(destIPHex[0])) + "." + to_string(static_cast<int>(destIPHex[1])) + "." + to_string(static_cast<int>(destIPHex[2])) + "." + to_string(static_cast<int>(destIPHex[3]));
    sourcePort = to_string(sourcePortInt);
    destinationPort = to_string(destPortInt);
    if (static_cast<int>(protocolHex) == 17) {
        protocol = "UDP";
    } else if (static_cast<int>(protocolHex) == 6) {
        protocol = "TCP";
    }
    timeToLive = static_cast<int>(timeToLiveHex);
    ipHeaderLength = static_cast<int>(headerLenInt);

    // Print out IP packet information
    cout << "--------------------------------------------" << endl;
    cout << "Source IP Address: " << sourceIP << ":" << sourcePort << endl;
    cout << "Destination IP Address: " << destinationIP << ":" << destinationPort << endl;
    cout << "Protocol: " << protocol << " | TTL: " << timeToLive << " | Header Length: " << to_string(ipHeaderLength) << endl;
    cout << "Offset: " << offset << endl;

}

// Load UDP packet info into variables
void processUDPPacket(uint8_t* buffer, int& packetLength, uint16_t& checksumValue, int offset) {
    uint8_t lengthHex[2] = {buffer[24 + offset], buffer[25 + offset]};
    uint8_t checksumHex[2] = {buffer[26 + offset], buffer[27 + offset]};

    // Store values
    uint16_t lengthInt = static_cast<uint16_t>((lengthHex[0] << 8) | lengthHex[1]);
    checksumValue = static_cast<uint16_t>((checksumHex[0] << 8) | checksumHex[1]); 
    packetLength = static_cast<int>(lengthInt);

    // Print value
    cout << "UDP packet length " << packetLength << "." << endl;
    cout << "--------------------------------------------" << endl; 
}

void processTCPPacket(uint8_t* buffer, uint16_t& checksumValue, int offset) {
    uint8_t checksumHex[2] = {buffer[36 + offset], buffer[37 + offset]};

    // Store values
    checksumValue = static_cast<uint16_t>((checksumHex[0] << 8) | checksumHex[1]); 

    // Print value
    cout << "TCP packet processed." << endl;
    cout << "--------------------------------------------" << endl; 
}

// Modify packet information for UDP
bool modifyPacketInformation(uint8_t* newPacket, string& sourceIP, string& destinationIP, string& sourcePort, string& destinationPort, int ipHeaderLength, int& timeToLive, uint16_t& ipChecksum, 
                                string lanIP, string wanIP, vector<string>& links, map<string, string>& portMap, int& firstAllocablePortN, int offset) {
    // Decrement TTL
    timeToLive -= 1;
    // cout << "Time to live:" << to_string(timeToLive) << endl;
    uint8_t ipBuff[4];
    uint8_t portBuff[2];

    // if from LAN to LAN (both src and dest are using NAT address)
    if (extractPrefix(lanIP) == extractPrefix(sourceIP) && extractPrefix(lanIP) == extractPrefix(destinationIP)) {
        cout << "LAN to LAN" << endl;
        // MAKE NO CHANGES.
    } 
    // if from LAN to WAN (src is using LAN IP)
    else if (extractPrefix(lanIP) == extractPrefix(sourceIP) && extractPrefix(destinationIP) != extractPrefix(lanIP) && extractPrefix(destinationIP) != extractPrefix(wanIP)) {
        // If the LANside source port has no mapping, allocate the first available WAN-side port to it.
        string combinedString = sourceIP + ":" + sourcePort;
        if (portMap.count(combinedString) == 0) {
            portMap[combinedString] = to_string(firstAllocablePortN);
            cout << "New port allocated for "  << sourceIP << " - " << sourcePort << ":" << to_string(firstAllocablePortN) << endl;
            firstAllocablePortN += 1;
        }
        sourceIP = wanIP;
        sourcePort = portMap[combinedString];

        cout << "LAN to WAN" << endl;
        cout << "New source: " << sourceIP << ":" << sourcePort << endl;
        //cout << "Before:" << endl;
        //printHexValues(newPacket, 28);

        // Modify packet with new sourceIP, new sourcePort
        ipAndPortToHex(sourceIP, sourcePort, ipBuff, portBuff);
        modifyPacketIPandPort(newPacket, ipBuff, portBuff, "source", offset);

        //cout << "After:" << endl;
        //printHexValues(newPacket, 28);
    }

    // if from WAN to LAN (dest is using WAN IP)
    else if (extractPrefix(wanIP) == extractPrefix(destinationIP) && extractPrefix(sourceIP) != extractPrefix(lanIP) && extractPrefix(sourceIP) != extractPrefix(wanIP)) {
        // Check if the destination port is mapped to a NAT-side port.
        int flag = 0;
        for (const auto& entry : portMap) {
            const string& wanPort = entry.second;
            if (destinationPort == wanPort) {
                extractLANandIP(entry.first, destinationPort, destinationIP);
                cout << "WAN to LAN" << endl;
                cout << "New dest: " << destinationIP << ":" << destinationPort << endl;
                flag = 1;
                break;
            }
        }
        if (flag == 1) {
            //cout << "Before:" << endl;
            //printHexValues(newPacket, 28);

            // Modify packet with new destIP, new destPort
            ipAndPortToHex(destinationIP, destinationPort, ipBuff, portBuff);
            modifyPacketIPandPort(newPacket, ipBuff, portBuff, "dest", offset);
            
            //cout << "After:" << endl;
            //printHexValues(newPacket, 28);
        }
        else {
            // Drop the packet: no mapping available.
            return false;
        }
    }

    // Modify TTL Field
    newPacket[8] = static_cast<uint8_t>(timeToLive);

    // Compute new IP Checksum
    uint8_t ipChecksumPacket[20];
    createIPChecksumPacket(newPacket, ipChecksumPacket, offset);
    uint16_t newIPChecksum = computeChecksum(ipChecksumPacket, 20 + offset);

    // Modify IP Checksum Field
    modifyPacketChecksum(newPacket, newIPChecksum, "IP", offset);

    //cout << "New IP Packet " << endl;
    //printHexValues(newPacket, 28);
    return true;
}




// Helper functions:

// Print out the hex contents of the buffer
void printHexValues(const uint8_t buffer[], int size) {
    for (int i = 0; i < size; i++) {
        cout << hex << static_cast<int>(buffer[i]) << " ";
    }
    cout << endl;
}

void printCharArrValues(unsigned char* charArray, int size) {
    for (int i = 0; i < size; i++) {
        cout << hex << (int)charArray[i] << " ";
    }
    cout << endl;
}

// Extract prefix of IP
string extractPrefix(string IP) {
    string prefix = "";
    int countPeriods = 0;
    for (char c: IP) {
        if (c == '.') {
            countPeriods += 1;
        }
        prefix += c;
        if (countPeriods == 3) {
            break;
        }
    }
    return prefix;
}

// Create IP Psuedoheader and Load UDP/TCP data
void createChecksumPacket(uint8_t buffer[], uint8_t* checksumBuffer, int length, int offset) {
    // Source IP
    checksumBuffer[0] = buffer[12];
    checksumBuffer[1] = buffer[13];
    checksumBuffer[2] = buffer[14];
    checksumBuffer[3] = buffer[15];

    // Destination IP
    checksumBuffer[4] = buffer[16];
    checksumBuffer[5] = buffer[17];
    checksumBuffer[6] = buffer[18];
    checksumBuffer[7] = buffer[19];

    // Reserved
    checksumBuffer[8] = 0x0;

    // Protocol
    checksumBuffer[9] = buffer[9];

    // Compute Length
    int lenField = length - 20 - offset;
    // cout << "Psuedoheader Protocol Length: " << lenField << endl;

    // Convert computed int length into a uint_8 length
    checksumBuffer[10] = static_cast<uint8_t>(lenField >> 8);
    checksumBuffer[11] = static_cast<uint8_t>(lenField);

    /*
    28; udp length = 8
    0-11 already from the Psuedoheader
    20th byte is first byte of UDP
    check[12] = buffer[20]
    check[13] = buffer[21]
    check[14] = buffer[22]
    check[15] = buffer[23]
    check[16] = buffer[24]
    check[17] = buffer[25]
    check[18] = buffer[26]
    check[19] = buffer[27]
    */
    for (int i = 12; i < 12 + length - 20 - offset; i++) {
        checksumBuffer[i] = buffer[i + 8 + offset];
    }

    // Print (Debug)
    // printHexValues(checksumBuffer, 12 + length - 20);
}

// Remove IP Checksum info and create individual packet
void createIPChecksumPacket(uint8_t buffer[], uint8_t* checksumBuffer, int offset) {
    for (int i = 0; i < 20 + offset; i++) {
        if (i == 10 || i == 11) {
            checksumBuffer[i] = 0x0;
        } else {
            checksumBuffer[i] = buffer[i];
        }
    }
    // cout << "IP Checksum Packet: " << endl;
    // printHexValues(checksumBuffer, 20);
}

// Convert IP Address and Port to uint8_t 
void ipAndPortToHex(string IP, string port, uint8_t* ipBuffer, uint8_t* portBuffer) {
    string currInteger = "";
    string stringArr[4];
    int iterator = 0;

    // Convert IP string into array
    for (char c : IP) {
        if (c == '.') {
            stringArr[iterator] = currInteger;
            iterator += 1;
            currInteger = "";
        } else {
        currInteger += c;
        }
    }
    stringArr[iterator] = currInteger;

    // Convert string array into uint8_t array
    for (int i = 0; i < 4; i++) {
        ipBuffer[i] = static_cast<uint8_t>(stoi(stringArr[i]));
    }

    // Convert port string into uint8_t representation
    int portInt = stoi(port);
    portBuffer[0] = static_cast<uint8_t>(portInt >> 8);
    portBuffer[1] = static_cast<uint8_t>(portInt);
}

// Modify the IP Packet with new IP and Port
void modifyPacketIPandPort(uint8_t* packet, uint8_t ipBuff[4], uint8_t portBuff[2], string code, int offset) {
    /*
    cout << "ipBUFF contents: ";
    printHexValues(ipBuff, 4);
    cout << endl;

    cout << "portBuff contents: ";
    printHexValues(portBuff, 2);
    cout << endl;

    cout << "modPacketIP before: ";
    printHexValues(packet, 28);
    */

    if (code == "source") {
        // Modify IP
        packet[12] = ipBuff[0];
        packet[13] = ipBuff[1];
        packet[14] = ipBuff[2];
        packet[15] = ipBuff[3];

        // Modify Port
        packet[20 + offset] = portBuff[0];
        packet[21 + offset] = portBuff[1];
    }
    else if (code == "dest") {
        // Modify IP
        packet[16] = ipBuff[0];
        packet[17] = ipBuff[1];
        packet[18] = ipBuff[2];
        packet[19] = ipBuff[3];

        // Modify Port
        packet[22 + offset] = portBuff[0];
        packet[23 + offset] = portBuff[1];
    }

    //cout << "modPacketIP after: ";
    //printHexValues(packet, 28);
}

// Modify the packet checksum depending on the protocol.
void modifyPacketChecksum(uint8_t* packet, uint16_t checksumValue, string protocol, int offset) {
    uint8_t convertedArr[2];
    convertedArr[0] = (checksumValue >> 8) & 0xff;
    convertedArr[1] = checksumValue & 0xff;
    if (protocol == "IP") {
        packet[10] = convertedArr[0];
        packet[11] = convertedArr[1];
    } else if (protocol == "UDP") {
        packet[26 + offset] = convertedArr[0];
        packet[27 + offset] = convertedArr[1];
    } else if (protocol == "TCP") {
        packet[36 + offset] = convertedArr[0];
        packet[37 + offset] = convertedArr[1];
    }
}


// Checksum class from provided github grading repo (quoted on Piazza)
// 
// https://github.com/CS118S23/spring23-project2/blob/f19b6e6afa305bef2cd06920c0181c5e7f4f0453/grader/packet_generate.py#L32-L64
class Checksum {
    private:
        int val;
    public:
        Checksum() : val(0) {}
    
    void add(uint8_t* buffer, int len) {
        for (int i = 0; i < len - 1; i += 2) {
            val += (buffer[i] << 8) + (buffer[i + 1]);
        }
        if (len % 2 == 1) {
            val += (buffer[len - 1] << 8);
        }
    }

    uint16_t finish() {
        while (val > 0xFFFF) {
            val = (val >> 16) + (val & 0xFFFF);
        }
        return ~val & 0xFFFF;
    }

};

uint16_t computeChecksum(uint8_t packet[], int lenPacket) {
    Checksum checksum;
    checksum.add(packet, lenPacket);
    return checksum.finish();
}
