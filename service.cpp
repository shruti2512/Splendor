
#include <stdio.h>   
#include <conio.h>
#include <iostream>
#include <stdlib.h>
#include <string> 
#include <xstring>
#include <sys/types.h>  
#include <winsock2.h>   
#include <ws2tcpip.h>
#include "CertAuth.h"
#include "SHA1.h"
#include "utils.h"
#pragma comment(lib, "Ws2_32.lib")

using namespace std;

const int MIN_PORT = 1024;
const int MAX_PORT = 65535;
const int MAX_REQ_PARTS = 256;		// max parts of a service location string
bool dbg_flag = true;				// change to false before deployment

char type_str[100];					// to get the service type from the user

const char * service_key_pair;		// to store the service's RSA key pair
const char * service_cert;			// to store the service's public key certificate

const char * MULTICAST_ADDR_STR = "225.0.0.1";
const int MULTICAST_PORT = 9666;

char * SERVICE_ADDR_STR = "";
int SERVICE_PORT = 0;
char SERVICE_NAME[50];
char SERVICE_TYPE[50];
char SERVICE_DESC[256];

char * get_directory_location();
char * register_service_location(char *, int);
void accept_client_connections();
void handle_communication_with_client(int);

int main(int argc, char *argv[]) 
{ 
	if (argc > 1)
	{
		for (int i=1; i<argc; i++)
		{
			if (_strcmpi(argv[i], "debug")==0)
			{
				dbg_flag = true;
				break;
			}
		}
	}

	WSADATA wsaData;	// Windows socket DLL structure

	// Load Winsock 2.0 DLL
	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
	{
		printf("WSAStartup() failed.\n");
		exit(-1);
	}

	// find out the hostname and IP address of this machine
	char hostname[50];
	struct hostent * entry;
	if (gethostname(hostname, sizeof(hostname)) == 0)
	{
		printf("Hostname = %s\n", hostname);
		if ((entry = gethostbyname(hostname)) != NULL)
		{
			SERVICE_ADDR_STR = (char *)calloc(16, sizeof(char));
			strcpy_s(SERVICE_ADDR_STR, 16, 
				inet_ntoa(*(struct in_addr *)entry->h_addr_list[0]));
			printf("IP Address = %s\n", SERVICE_ADDR_STR);
		}
	}
		
	// seed the pseudo random number generator now
	// for using it later to generate session keys for client communications
	srand((unsigned)time_t());

	// get keys and certificates from CA - these will be used in communication 
	// both with the directory and the client
	service_key_pair = generateRSAKeyPair(1024);
	const char * service_csr = generateCSR(service_key_pair);
	service_cert = getCertificate(service_csr);

	// ***** step 1 : get the directory location *****
	char *context;
	char * dir_ip_str = (char*)calloc(50, sizeof(char));
	char * dir_location = get_directory_location();
	strcpy_s(dir_ip_str, 50, strtok_s(dir_location, ":", &context));
	int dir_port = atoi(strtok_s(NULL, ":", &context));
	printf("Directory location received. IP = %s port = %d\n", dir_ip_str, dir_port);

	// ***** step 2 : connect to the directory and register this service *****
	char * response = register_service_location(dir_ip_str, dir_port);
	if (strstr(response, "OK") == response) // if response starts with "OK"
	{
		// ***** step 3 : accept connections from clients needing this service - receive message and send response *****
		accept_client_connections();
	}
	else
	{
		printf("Could not register the service with the directory.\n");
		printf("The directory returned : \n %s", response);
		printf("Press ENTER to exit.\n");
		getchar();
	}
	
	WSACleanup();	// Cleanup Winsock
	
	return 0;
} 

char * get_directory_location()
{
	int sock;      
	struct sockaddr_in mc_addr;
	struct sockaddr_in from_addr;
	int from_addr_len;				// length of the from_addr structure
	int send_len;					// length of sent message
	int recv_len;					// length of received message	
	char mc_ttl = 1;				// time to live (hop count) 

	// create a socket for sending to the multicast address
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		printf("socket() failed.\n");
		exit(-1);
	}

	// set the TTL (time to live/hop count) for the send
	if ((setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &mc_ttl, sizeof(mc_ttl))) < 0)
	{
		printf("setsockopt() failed.\n");
		exit(-1);
	}
	
	// construct a multicast address structure
	memset(&mc_addr, 0, sizeof(mc_addr));
	mc_addr.sin_family      = AF_INET;
	mc_addr.sin_addr.s_addr = inet_addr(MULTICAST_ADDR_STR);
	mc_addr.sin_port        = htons(MULTICAST_PORT);

	// prepare the from_addr structure - debug purpose only
	from_addr_len = sizeof(from_addr);
	memset(&from_addr, 0, from_addr_len);

	printf("Going to send a 'find' command to the directory locator on a multicast address. Press ENTER to proceed.\n");
	getchar();

	// prepare the find command
	char send_cmd[5];
	strcpy_s(send_cmd, sizeof(send_cmd), "find");
	send_len = strlen(send_cmd);

	// send the 'find' command to directory locator
	socket_send_to(sock, send_cmd, send_len, &mc_addr, sizeof(mc_addr), "directory locator");

	// receive the response from directory locator
	char * dir_location;
	socket_recv_from(sock, &dir_location, &recv_len, &from_addr, &from_addr_len, "directory locator");

	if (dbg_flag) printf("Received %d bytes from %s\n", recv_len, inet_ntoa(from_addr.sin_addr));
	if (dbg_flag) printf("Data received : %s\n", dir_location);

	// close the UDP socket
	closesocket(sock);

	return dir_location;
}

char * register_service_location(char *dir_ip_str, int dir_port)
{
	printf("This service will run on this machine with IP address : %s\n", SERVICE_ADDR_STR);
	printf("Enter the type of this service : ");
	scanf_s("%s", SERVICE_TYPE, sizeof(SERVICE_TYPE));
	printf("Enter a description for this service : ");
	scanf_s("%s", SERVICE_DESC, sizeof(SERVICE_DESC));
	//TODO remove "|" and ":", if any, from the service description text
	printf("Enter a name for this service : ");
	scanf_s("%s", SERVICE_NAME, sizeof(SERVICE_NAME));
	printf("Enter the port on which this service will run : ");
	scanf_s("%d", &SERVICE_PORT);
	if (SERVICE_PORT<MIN_PORT || SERVICE_PORT>MAX_PORT)
	{
		SERVICE_PORT = (rand()%64512)+1024;
		printf("Port should be between 1024 and 65535. ");
		printf("Defaulting to a random port number %d", SERVICE_PORT);
	}
	// TODO insert code for getting attributes

	// construct the register command
	char * reg_command = (char*) malloc(MAX_MSG_LEN);
	strcpy_s(reg_command, MAX_MSG_LEN, "command:register|type:");
	strcat_s(reg_command, MAX_MSG_LEN, SERVICE_TYPE);
	strcat_s(reg_command, MAX_MSG_LEN, "|name:");
	strcat_s(reg_command, MAX_MSG_LEN, SERVICE_NAME);
	strcat_s(reg_command, MAX_MSG_LEN, "|description:");
	strcat_s(reg_command, MAX_MSG_LEN, SERVICE_DESC);
	strcat_s(reg_command, MAX_MSG_LEN, "|ip:");
	strcat_s(reg_command, MAX_MSG_LEN, SERVICE_ADDR_STR);
	strcat_s(reg_command, MAX_MSG_LEN, "|port:");
	char temp[6];
	_itoa_s(SERVICE_PORT, temp, 6, 10);
	strcat_s(reg_command, MAX_MSG_LEN, temp);
	//TODO insert code for adding the attributes to the register command

	// create socket
	SOCKET sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) 
	{
		printf("Error at socket(): %ld\n", WSAGetLastError());
		WSACleanup();
		exit(-1);	
	}

	// prepare the directory address structure and connect the socket using it
	struct sockaddr_in dir_addr;
	memset(&dir_addr, 0, sizeof(dir_addr));
	dir_addr.sin_family = AF_INET;
	dir_addr.sin_addr.s_addr = inet_addr(dir_ip_str);
	dir_addr.sin_port = htons(dir_port);

	// connect to directory
	socket_connect(sock, &dir_addr, sizeof(dir_addr), "directory");

	// 1. service sends its public key certificate to the directory
	socket_send(sock, service_cert, strlen(service_cert));

	// 2. service receives the directory's public key certificate
	char * dir_cert;
	int temp_len;
	socket_recv(sock, &dir_cert, &temp_len);
	
	// 3. service verifies the directory's public key certificate
	if (!verify_certificate(dir_cert))
	{
		printf("The certificate is not valid. Closing connection now.\n");
		socket_exit(sock);
	}

	// 4. encrypt the register command using the public key of the directory
	const char * enc_reg_command;
	int enc_reg_command_len;
	encryptData(dir_cert, reg_command, &enc_reg_command, &enc_reg_command_len);

	// 5. service signs the hash of register request with its private key
	CSHA1 sha1;
	sha1.Update((UINT_8*)enc_reg_command, enc_reg_command_len);
	sha1.Final();
	unsigned char * strReport = (unsigned char*) calloc(50, sizeof(unsigned char));
	sha1.GetHash(strReport);
	const char * hash_enc_reg_command = (char*)strReport;
	const char * sig_hash_enc_reg_command;
	int sig_hash_enc_reg_command_len;
	signData(service_key_pair, hash_enc_reg_command, 
		&sig_hash_enc_reg_command, &sig_hash_enc_reg_command_len);
	free(strReport);

	// 6. service sends a) register request and 
	// b) signed hash of the register request to the directory
	socket_send(sock, enc_reg_command, enc_reg_command_len, "directory");
	socket_send(sock, sig_hash_enc_reg_command, sig_hash_enc_reg_command_len, "directory");

	// 7. service receives response from the directory
	char * response;
	socket_recv(sock, &response, &temp_len);
	
	if (dbg_flag) printf("Recieved %d bytes from the directory.\n", temp_len);
	if (dbg_flag) printf("Data received : %s\n", response);

	closesocket(sock);

	return response;
}

void accept_client_connections()
{
	printf("Starting service now and waiting for client connections.\n");

	// create socket
	SOCKET sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) 
	{
		printf("Error at socket(): %ld\n", WSAGetLastError());
		WSACleanup();
		exit(-1);	
	}

	// prepare the service address structure and connect the socket using it
	struct sockaddr_in svc_addr;
	memset(&svc_addr, 0, sizeof(svc_addr));
	svc_addr.sin_family = AF_INET;
	svc_addr.sin_addr.s_addr = inet_addr(SERVICE_ADDR_STR);
	svc_addr.sin_port = htons(SERVICE_PORT);

	// bind and listen on the socket
	socket_bind_listen(sock, &svc_addr, sizeof(svc_addr));

	struct sockaddr_in from_addr;
	int from_addr_len = sizeof(from_addr);
	SOCKET accepted_sock;
	while(1)
	{
		memset(&from_addr, 0, sizeof(from_addr));

		// accept client connections
		accepted_sock = socket_accept(sock, &from_addr, &from_addr_len);
		printf("Accepted a client connection from %s:%d\n", 
			inet_ntoa(from_addr.sin_addr), ntohs(from_addr.sin_port));

		// handle communication with this client
		handle_communication_with_client(accepted_sock);
				
		closesocket(accepted_sock);
		printf("Closed client connection from %s:%d\n", 
			inet_ntoa(from_addr.sin_addr), ntohs(from_addr.sin_port));
	}
	
	closesocket(sock);
}

void handle_communication_with_client(int accepted_sock)
{
	/***** service -> client communication sequence starts here *****/
	
	int temp_recv_len; // used to store the length of data received from client

	// 1. service receives client certificate
	char * client_cert;
	socket_recv(accepted_sock, &client_cert, &temp_recv_len);

	// 2. service verifies the client certificate
	if (!verify_certificate(client_cert))
	{
		printf("The client certificate is not valid.\nClosing connection with client now...\n");
		// can also send a terminate message to client if reqd
		return;
	}

	// 3. service generates session key and encrypt it with client's public key
	int rand_num = rand(); // this gives a pseudo-random number - initialized in accept_client_connections()
	char session_key [30];
	sprintf_s(session_key, sizeof(session_key), "%d", rand_num);
	const char * enc_sess_key;
	int enc_sess_key_len;
	encryptData(client_cert, session_key, &enc_sess_key, &enc_sess_key_len);
	
	// 4. service sign the hash of the encrypted session key with its private key
	CSHA1 sha1;
	sha1.Update((UINT_8*)enc_sess_key, enc_sess_key_len);
	sha1.Final();
	unsigned char * strReport = (unsigned char*) calloc(50, sizeof(unsigned char));
	sha1.GetHash(strReport);
	const char * hash_enc_sess_key = (char*)strReport;
	const char * sig_hash_enc_sess_key;
	int sig_hash_enc_sess_key_len;
	signData(service_key_pair, hash_enc_sess_key, &sig_hash_enc_sess_key, &sig_hash_enc_sess_key_len);
	free(strReport);

	// 5. service sends its a) certificate b) encrypted session key 
	// c) signed hash of encrypted session key
	socket_send(accepted_sock, service_cert, strlen(service_cert));
	socket_send(accepted_sock, enc_sess_key, enc_sess_key_len);
	socket_send(accepted_sock, sig_hash_enc_sess_key, sig_hash_enc_sess_key_len);

	// 6. service receives message (and all future messages in this session) from client 
	// with AES encryption using the session key
	char * test_recv;
	int test_recv_len;
	socket_recv(accepted_sock, &test_recv, &test_recv_len);
	printf("Received the following message from the client : %s\n", test_recv);
	// TODO decrypt the message with AES decryption using session key
	const char * dec_test_recv = test_recv;
	printf("Decrypted message from client : %s\n", dec_test_recv);

	// 7. service responsds to client with AES encryption using the session key
	char * test_send = "Hello from service.";
	char * enc_test_send = test_send; // TODO do AES encryption here with session_key
	int enc_test_send_len = strlen(test_send);
	socket_send(accepted_sock, enc_test_send, enc_test_send_len);
	printf("Sending response to the client (plain text) : %s\n", test_send);
	printf("Sending response to the client (encrypted) : %s\n", enc_test_send);
	
	// one message passing between service and client complete - simulation stops here

//	/************************* DEBUG *************************/
//	// receive message from client
//	char * msg_recv;
//	int msg_recv_len;
//	socket_recv(accepted_sock, &msg_recv, &msg_recv_len);
//	printf("Received the following message from the client : %s\n", msg_recv);

//	// send response to the client
//	char * msg_to_send = "Sample response from service.";
//	socket_send(accepted_sock, msg_to_send, strlen(msg_to_send));
//	printf("Sending response to the client : %s\n", msg_to_send);
//	/*********************************************************/
}
