
#include <stdio.h>   
#include <conio.h>
#include <iostream>
#include <stdlib.h>     
#include <string> 
#include <xstring>
#include <sys/types.h>  
#include <winsock2.h>   
#include <ws2tcpip.h>    
#include "ServiceInfo.h"
#include "CertAuth.h"
#include "SHA1.h"
#include "utils.h"

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

const int MAX_REQ_PARTS = 256;	// max parts of a service location string
const int MAX_SERVICES = 100;	// max processed services per service type
bool dbg_flag = true;				// change to false before deployment

char type_str[100];				// to get the service type from the user

const char * client_key_pair;		// to store the client's RSA key pair
const char * client_cert;			// to store the client's public key certificate

const char * MULTICAST_ADDR_STR = "225.0.0.1";
const int MULTICAST_PORT = 9666;

char * get_directory_location();
char * get_service_location(char *, int);
void connect_to_service(char *, int);
void handle_communication_with_service(int);
ServiceInfo get_service_info(char *);

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

	// get keys and certificates from CA - these will be used in communication 
	// both with the directory and the client
	client_key_pair = generateRSAKeyPair(1024);
	const char * client_csr = generateCSR(client_key_pair);
	client_cert = getCertificate(client_csr);

	// ***** step 1 : get the directory location *****
	char *context;
	char * dir_ip_str = (char*)calloc(50, sizeof(char));
	strcpy_s(dir_ip_str, 50, strtok_s(get_directory_location(), ":", &context));
	int dir_port = atoi(strtok_s(NULL, ":", &context));
	printf("Directory location received. IP = %s port = %d\n", dir_ip_str, dir_port);

	while(1)
	{
		// ***** step 2 : connect to the directory and get the service location *****
		char * svc_loc_str = get_service_location(dir_ip_str, dir_port);

		if (_strcmpi(svc_loc_str, "exit")==0) break; // exit criteria

		// for service types not found in directory, continue with the loop
		if (strchr(svc_loc_str, ']') == NULL) continue;
		
		ServiceInfo services[MAX_SERVICES];
		int svc_index=0;
		char * svc_loc_part = strtok_s(svc_loc_str, "]", &context);
		services[svc_index++] = get_service_info(svc_loc_part);
		while((svc_loc_part = strtok_s(NULL, "]", &context)) != NULL && (svc_index < MAX_SERVICES))
		{
			services[svc_index++] = get_service_info(svc_loc_part);
		}

		printf("%d services information received from directory.\n", svc_index);
		for (int i=0; i<svc_index; i++)
		{
			printf("%d) Name : %s\n    IP    : %s\n    Port : %d\n\n", 
				i+1, services[i].m_name, services[i].m_ip, services[i].m_port);
		}
		int choice;
		printf("Enter the service number you want to connect : ");
		scanf_s("%d", &choice);
		choice--; // zero indexed array

		// if proper service location was not received, do not proceed with connecting to service
		char *svc_ip = services[choice].m_ip;
		int svc_port = services[choice].m_port;
		if (svc_ip==NULL || svc_port==0)
		{
			continue;
		}

		// ***** step 3 : connect to the service, send a test message and receive a test response *****
		connect_to_service(svc_ip, svc_port);
	}

	WSACleanup();	// Cleanup Winsock
	
	return 0;
}

char * get_directory_location()
{
	int sock;
	struct sockaddr_in mc_addr;
	struct sockaddr_in from_addr;
	int from_addr_len;				// length of the from_addr structur
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

	// close UDP socket
	closesocket(sock);

	return dir_location;
}

char * get_service_location(char *dir_ip_str, int dir_port)
{
	printf("\nEnter the type of service you need (type 'exit' to exit the program) : ");
	scanf_s("%s", type_str, 100);

	if (_strcmpi(type_str, "exit")==0) return type_str; // exit criteria

	// prepare the query command
	char * query_command = (char*) malloc(MAX_MSG_LEN);
	strcpy_s(query_command, MAX_MSG_LEN, "command:query|type:");
	strcat_s(query_command, MAX_MSG_LEN, type_str);

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

	// 1. client sends its public key certificate to the directory
	socket_send(sock, client_cert, strlen(client_cert));

	// 2. client receives the directory's public key certificate
	char * dir_cert;
	int temp_len;
	socket_recv(sock, &dir_cert, &temp_len);
	
	// 3. service verifies the directory's public key certificate
	if (!verify_certificate(dir_cert))
	{
		printf("The certificate is not valid. Closing connection now.\n");
		socket_exit(sock);
	}

	// 4. encrypt the query command using the public key of the directory
	const char * enc_query_command;
	int enc_query_command_len;
	encryptData(dir_cert, query_command, &enc_query_command, &enc_query_command_len);

	// 5. client signs the hash of query request with its private key
	CSHA1 sha1;
	sha1.Update((UINT_8*)enc_query_command, enc_query_command_len);
	sha1.Final();
	unsigned char * strReport = (unsigned char*) calloc(50, sizeof(unsigned char));
	sha1.GetHash(strReport);
	const char * hash_enc_query_command = (char*)strReport;
	const char * sig_hash_enc_query_command;
	int sig_hash_enc_query_command_len;
	signData(client_key_pair, hash_enc_query_command, 
		&sig_hash_enc_query_command, &sig_hash_enc_query_command_len);
	free(strReport);

	// 6. client sends a) query request and 
	// b) signed hash of the query request to the directory
	socket_send(sock, enc_query_command, enc_query_command_len, "directory");
	socket_send(sock, sig_hash_enc_query_command, sig_hash_enc_query_command_len, "directory");

	// 7. service receives response from the directory
	char * response;
	socket_recv(sock, &response, &temp_len);

	if (dbg_flag) printf("Recieved %d bytes from the directory.\n", temp_len);
	if (dbg_flag) printf("Data received : %s\n", response);

	closesocket(sock);

	return response;
}

void connect_to_service(char *svc_ip_str, int svc_port)
{
	char resp;
	printf("Do you want to connect to service and send/receive test messages (y/n) ? \n");
	resp = _getch();
	if (resp=='n') return;

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
	svc_addr.sin_addr.s_addr = inet_addr(svc_ip_str);
	svc_addr.sin_port = htons(svc_port);
	if (connect(sock, (struct sockaddr *)&svc_addr, sizeof(svc_addr))==SOCKET_ERROR)
	{
		printf("connect() to service failed with error = %ld\n", WSAGetLastError());
		exit(-1);
	}
	printf("Connected to service at %s:%d\n", svc_ip_str, svc_port);

	// handle communication with this service
	handle_communication_with_service(sock);

	closesocket(sock);
	printf("Closed connection with service at %s:%d\n", svc_ip_str, svc_port);
}

void handle_communication_with_service(int sock)
{
	/***** client -> service communication sequence starts here *****/

	int temp_len; // used to store the length of data received from service

	// 1. send the certificate to service
	socket_send(sock, client_cert, strlen(client_cert), "service");

	// 2. client receives a) service's certificate b) encrypted session key 
	// c) signed hash of encrypted session key
	char * service_cert;
	socket_recv(sock, &service_cert, &temp_len, "service");
	char * enc_sess_key;
	int enc_sess_key_len;
	socket_recv(sock, &enc_sess_key, &enc_sess_key_len, "service");
	char * sig_hash_enc_sess_key;
	int sig_hash_enc_sess_key_len;
	socket_recv(sock, &sig_hash_enc_sess_key, &sig_hash_enc_sess_key_len, "service");
	
	// 3. client verifies service certificate
	if (!verify_certificate(service_cert))
	{
		printf("The service certificate is not valid.\nClosing connection with service now...\n");
		// can also send a terminate message to service
		return;
	}

	// 4. client recovers the hash from service signed data 
	// and calculates hash of encrypted session key - matches both
	const char * rec_hash_enc_sess_key = 
		recoverSignedData(service_cert, sig_hash_enc_sess_key, sig_hash_enc_sess_key_len);
	CSHA1 sha1;
	sha1.Update((UINT_8*)enc_sess_key, enc_sess_key_len);
	sha1.Final();
	unsigned char * strReport = (unsigned char*) calloc(50, sizeof(unsigned char));
	sha1.GetHash(strReport);
	const char * calc_hash_enc_sess_key = (char*)strReport;
	if (strcmp(rec_hash_enc_sess_key, calc_hash_enc_sess_key) != 0)
	{
		printf("Signature validation failed.\nClosing connection with service now...\n");
		// can also send a terminate message to service
		return;
	}
	free(strReport);

	// 5. client decrypts the encrypted session key to get the session key
	const char * session_key = decryptData(client_key_pair, enc_sess_key, enc_sess_key_len);

	// 6. client sends message to server (and all future messages too) 
	// with AES encryption using session key
	char * test_send = "Hello from client.";
	char * enc_test_send = test_send; // TODO do AES encryption here with session_key
	int enc_test_send_len = strlen(test_send);
	socket_send(sock, enc_test_send, enc_test_send_len, "service");
	printf("Sent a test message to the service (plain text) : %s\n", test_send);
	printf("Sent a test message to the service (encrypted) : %s\n", enc_test_send);

	// 7. client receives response from server with AES encryption using session key
	char * test_recv;
	int test_recv_len;
	socket_recv(sock, &test_recv, &test_recv_len, "service");
	printf("Received the following response from the service : %s\n", test_recv);
	// TODO decrypt the message with AES decryption using session key
	const char * dec_test_recv = test_recv;
	printf("Decrypted message from service : %s\n", dec_test_recv);

	// one message passing between service and client complete - simulation stops here

//	/************************* DEBUG *************************/
//	// send test message to service
//	char * msg_to_send = "Test message to service.";
//	socket_send(sock, msg_to_send, strlen(msg_to_send), "service");
//	printf("Sent a test message to the service: %s\n", msg_to_send);
//
//	// get response from service
//	char * msg_recv;
//	int msg_recv_len;
//	socket_recv(sock, &msg_recv, &msg_recv_len, "service");
//	printf("Received the following response from the service : %s\n", msg_recv);
//	/*********************************************************/
}

ServiceInfo get_service_info(char * svc_loc_str)
{
	// break the service location string into parts to get service info
	char * context;
	char * req_parts[MAX_REQ_PARTS];
	char * tok;

	int num_parts = 0;
	req_parts[num_parts++] = strtok_s(svc_loc_str, "|", &context);
	while ((tok=strtok_s(NULL, "|", &context)) != NULL)
	{
		req_parts[num_parts++] = tok;
	}

	// parse all the parts and retrieve the service location info
	char *name = NULL, *value = NULL;
	char *svc_type = NULL, *svc_name = NULL, *svc_ip = NULL;
	int svc_port = 0;
	//printf("Service location received.\n");
	for(int i=0; i<num_parts; i++)
	{
		name = strtok_s(req_parts[i], ":", &context);
		value = strtok_s(NULL, ":", &context);
		if(_strcmpi(name, "name")==0)
		{
			svc_name = value;
			//printf("Name = %s\n", svc_name);
		}
		else if(_strcmpi(name, "ip")==0)
		{
			svc_ip = value;
			//printf("IP = %s\n", svc_ip);
		}
		else if(_strcmpi(name, "port")==0)
		{
			svc_port = atoi(value);
			//printf("Port = %d\n", svc_port);
		}
		else // could be service attributes
		{
			//printf("%s = %s\n", name, value);
		}
	}
	return ServiceInfo(svc_name, svc_ip, svc_port);
}
