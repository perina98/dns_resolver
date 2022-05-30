#include "dns.h"

using namespace std;

/**
 * Check blacklist for domain
 *
 * @param filename Blacklist file name
 * @param domain Domain to filter
 * @return 1 if Domain in blacklist, 0 otherwise
 */
int searchFile(string filename,string domain){
    ifstream ifile(filename);
    string str;
    // convert domain string to lowercase for matching with input file
    for_each(domain.begin(), domain.end(), [](char & c) {
        c = ::tolower(c);
    });

    vector<string> domainArray;
    string subdomain;
    istringstream domainStream(domain);
    // split domain by dots
    while (getline(domainStream, subdomain, '.')) {
        domainArray.push_back(subdomain);
    }

    vector<string> fileLineArray;
    string fileLine;

    // iterate over file and search for domain
    while (getline(ifile, str)) {
        if(str.size() > 0){
            if(str.at(0) == '#'){
                continue;
            }
            // convert line string to lowercase for matching with input file
            for_each(str.begin(), str.end(), [](char & c) {
                c = ::tolower(c);
            });
            istringstream fileLineStream(str);
            while (getline(fileLineStream, fileLine, '.')) {
                fileLineArray.push_back(fileLine);
            }

            if((fileLineArray.size() <= domainArray.size()) && fileLineArray.size() > 0){
                int i = 0;
                while(domainArray[domainArray.size()-1 -i] == fileLineArray[fileLineArray.size()-1 -i]){
                    if(fileLineArray.size()-1 -i == 0){
                        return 1;
                    }
                    i++;
                }
            }
            
            fileLineArray.clear();
        }
    } 
    domainArray.clear();
    return 0;
}

/**
 * Check args
 *
 * @param filename Blacklist file name
 * @param server Server name / address
 * @return 1 if failed, 0 on success
 */
int argsCheck(string server,string filename){
    if(server == ""){
        fprintf(stderr, "Server nezadany\n");
        return 1;
    }
    else if(filename == ""){
        fprintf(stderr, "Subor nezadany\n");
        return 1;
    } else {
        ifstream ifile(filename);
        if(!ifile){
            fprintf(stderr, "Subor neexistuje\n");
            return 1;
        }
        return 0;
    }
}

/**
 * Get address from hostname
 *
 * @param hostname hostname string
 * @return translated hostname or blank string on fail
 */
string getAddr(const char *hostname){
    struct addrinfo hints, *res;
    string addrstr;
    memset(&hints,0,sizeof(hints));
    hints.ai_family  = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // getaddrinfo used strictly to translate server given by -s param
    if(getaddrinfo (hostname, NULL, &hints, &res) != 0){
        return("");
    }
    
    inet_ntop (res->ai_family, &((struct sockaddr_in *) res->ai_addr)->sin_addr, (char*) addrstr.c_str(), 128);
    return addrstr.c_str();
}


int main(int argc, char **argv)
{
    int opt;
    int port = 53;
    string server;
    string filename;

    // check for program args and set implicit values
    while ((opt = getopt (argc, argv, "hs:f:p:")) != -1)
    {
        switch (opt)
        {
            case 'h':
                printf("Volanie programu:\n");
                printf("./dns -s server [-p port] -f filter_file\n");
                exit(0);
            case 's':
                server = optarg;
                break;
            case 'f':
                filename = optarg;
                break;
            case 'p':
                if (atoi(optarg) < 0 || atoi(optarg) > 65535 || !isdigit(*optarg))
                {
                    fprintf(stderr, "Zle zadany port\n");
                    exit(3);
                }
                port = atoi(optarg);
                break;
            default:
                return (1);
        }
    }

    if(argsCheck(server,filename)){
        exit(1);
    }
   
    // Opening AF_INET6 DNS socket 
    int UDPSocket = socket(AF_INET6,SOCK_DGRAM,0);
    if(UDPSocket < 0){
        fprintf(stderr, "Socket sa nepodarilo otvorit");
    }

    // setting up mainServer and client for comunication
    struct sockaddr_in6 mainServer;
    struct sockaddr_in6 client;
    memset(&mainServer, 0, sizeof(mainServer)); 
    memset(&client, 0, sizeof(client)); 
    mainServer.sin6_family = AF_INET6;
    mainServer.sin6_addr= IN6ADDR_ANY_INIT;
    mainServer.sin6_port = htons(port);


    // bind UDPSocket to mainServer
    if (bind(UDPSocket,(struct sockaddr *)(&mainServer),sizeof(mainServer)) < 0)  
    {
        fprintf(stderr,"Nepodarilo sa vytvorit spojenie s portom %d.\n",port);
        exit(1);
    }

    int ClientLen = sizeof(client);
    int request;

    // run as server until stopped with signal
    while(1){
        char buffer[1024];
        memset(&client, 0, sizeof(client)); 
        // receive data from client to find out his request
        request = recvfrom(UDPSocket,(char *)buffer,sizeof(buffer),MSG_WAITALL,(struct sockaddr *) &client,(socklen_t *) &ClientLen);
        if(request == -1){
            fprintf(stderr, "Nepodarilo sa prijat otazku od klienta");
            exit(1);
        }
        buffer[request] = '\0'; // terminane buffer with \0 char

        // set up forking
        int pid;
        if((pid = fork()) == 0){

            uint16_t* buffer_full = (uint16_t*) buffer;

            int pos = 13; // domain starts here becouse of the packet structure
            int last = pos;
            int length = buffer[pos - 1]; // checking for dots
            string domain;

            while(length != 0){
                while(pos< last + length){
                    domain += buffer[pos];
                    pos++;
                }

                length = buffer[pos];
                pos++;
                last = pos;
                if(length != 0){ // if lengths isnt 0 then we should insert dot to complete domain format. As represented in packet, numbers represent str length
                    domain += '.';
                }
            }
            int index;
            if(pos % 2){ // check for correct format and if not correct then move the index
                buffer_full = (uint16_t*)(((char*) buffer_full) + 1);
                index = (pos-1) /2;
            } else{
                index = pos / 2;
            }
            uint16_t type = buffer_full[index];
            // check for domain blacklist status  and qtype
            dnshdr *dns_buffer = (dnshdr*) buffer;
            if(searchFile(filename, domain)){
                dns_buffer->rcode = 5;
            }
            if(ntohs(type) != 1){
                dns_buffer->rcode = 4;
            }
            if((searchFile(filename, domain)) || (ntohs(type) != 1)){
                dns_buffer->qr = 1;
                int response = sendto(UDPSocket, dns_buffer,request, 0, (const struct sockaddr *) &client,  ClientLen);
                if(response == -1){
                    fprintf(stderr, "Nepodarilo sa poslat odpoved klientovi");
                    exit(1);
                }
                close(UDPSocket);
                exit(0);
            }

            
            // set socket for comunication with provided dns server (-s server)
            int domainSocket = socket(AF_INET,SOCK_DGRAM,0);
            if(domainSocket < 0){
                fprintf(stderr, "Socket sa nepodarilo otvorit");
            }

            // setup dns server
            struct sockaddr_in domainServer;
            memset(&domainServer, 0, sizeof(domainServer)); 
            domainServer.sin_family = AF_INET;
            domainServer.sin_addr.s_addr = inet_addr(getAddr(server.c_str()).c_str());
            domainServer.sin_port = htons(53);

            int ClientLen1 = sizeof(domainServer);
            // send request to dns server
            int sntt = sendto(domainSocket, (char *)buffer,request, 0, (const struct sockaddr *) &domainServer,  ClientLen1); 
            if(sntt == -1){
                fprintf(stderr, "Nepodarilo sa kontaktovat DNS server");
                exit(1);
            }
            // receive answer from dns server
            request = recvfrom(domainSocket,(char *)buffer,sizeof(buffer),0,(struct sockaddr *) &domainServer,(socklen_t *) &ClientLen1);
            if(request == -1){
                fprintf(stderr, "Odpoved od DNS serveru nebola prijata");
                exit(1);
            }
            buffer[request] = '\0'; 
            // send response to client.
            int response = sendto(UDPSocket, (char *)buffer,request, 0, (const struct sockaddr *) &client,  ClientLen);
            if(response == -1){
                fprintf(stderr, "Nepodarilo sa poslat odpoved klientovi");
                exit(1);
            }

            close(UDPSocket);
            exit(0);
        }   
    }

  return 0;
}