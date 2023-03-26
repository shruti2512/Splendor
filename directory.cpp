// directory.cpp : Defines the entry point for the console application.
#include "stdafx.h"

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

const int MAX_REQ_PARTS = 256;
bool dbg_flag = true;				// change to false before deployment
bool SHUTDOWN = false;
const int MAX_REQ = 20;
int REQ_CNT = 0;
dbUtil db_util;

char * DIR_ADDR_STR = "";
const int DIR_PORT = 9999;

const char * MULTICAST_ADDR_STR = "225.0.0.1";
const int MULTICAST_PORT = 9666;

const char * dir_key_pair;		// to store the directory's RSA key pair
const char * dir_cert;			// to store the directory's public key certificate

unsigned int __stdcall directory_locator(void *);
unsigned int __stdcall directory(void *);
unsigned int __stdcall handle_connection(void *);
const char * process_request(char *);
const char * do_query_request(char **, int);
const char * do_register_request(char **, int);

struct dir_request
{
	SOCKET from_sock;
	struct sockaddr_in from_addr;
};

//int main(int argc, char ** argv)
int main(int argc, char* argv[])
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
	
	// start the directory locator
	HANDLE hThread1;
	unsigned threadID1;
	hThread1 = (HANDLE) _beginthreadex(NULL, 0, &directory_locator, NULL, 0, &threadID1);

	// start the directory
	HANDLE hThread2;
	unsigned threadID2;
	hThread2 = (HANDLE) _beginthreadex(NULL, 0, &directory, NULL, 0, &threadID2);

	WaitForSingleObject(hThread1, INFINITE);
	WaitForSingleObject(hThread2, INFINITE);

	CloseHandle(hThread2);
}

unsigned int __stdcall directory_locator(void *a)
{
	if (dbg_flag) printf("Directory locator activated.\n\n");
	
	int sock;                     
	int flag_on = 1;              
	struct sockaddr_in mc_addr;   
	char send_str[MAX_MSG_LEN];
	char recv_str[MAX_MSG_LEN];

	int recv_len;                 /* length of string received */
	struct ip_mreq mc_req;        /* multicast request structure */
	struct sockaddr_in from_addr; /* packet source */
	int from_len;                 /* source addr length */ 

	WSADATA wsaData;              /* Windows socket DLL structure */

	// Load Winsock 2.0 DLL

	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) 
	{
		fprintf(stderr, "WSAStartup() failed");
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
			DIR_ADDR_STR = (char *)calloc(16, sizeof(char));
			strcpy_s(DIR_ADDR_STR, 16, 
				inet_ntoa(*(struct in_addr *)entry->h_addr_list[0]));
			printf("IP Address = %s\n", DIR_ADDR_STR);
		}
	}
		
	// create socket to join multicast group on
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) 
	{
		perror("socket() failed");
		exit(-1);
	}

	// set reuse port to on to allow multiple binds per host
	if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&flag_on, 
		sizeof(flag_on))) < 0)
	{
		printf("setsockopt() failed.\n");
		exit(-1);
	}

	// construct a multicast address structure
	memset(&mc_addr, 0, sizeof(mc_addr));
	mc_addr.sin_family      = AF_INET;
	mc_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	mc_addr.sin_port        = htons(MULTICAST_PORT); 

	// bind to multicast address to socket
	if ((bind(sock, (struct sockaddr *) &mc_addr,sizeof(mc_addr))) < 0) 
	{
		printf("bind() failed.\n");
		exit(-1);
	}

	// construct an IGMP join request structure
	mc_req.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR_STR);
	mc_req.imr_interface.s_addr = htonl(INADDR_ANY);

	// send an ADD MEMBERSHIP message via setsockopt
	if ((setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,/*(char*) &mc_req,*/ 
		(const char FAR*) &mc_req, sizeof(mc_req))) < 0) 
	{
		printf("setsockopt() failed.\n");
		exit(-1);
	} 

	while(1) // loop until the main program exits and kills this thread
	{
		memset(recv_str, 0, sizeof(recv_str));
		from_len = sizeof(from_addr);
		memset(&from_addr, 0, from_len);

		// block waiting to receive a packet
		if ((recv_len = recvfrom(sock, recv_str, MAX_MSG_LEN, 0,
			(struct sockaddr*)&from_addr, &from_len)) < 0) 
		{
			printf("recvfrom() failed.\n");
			exit(-1);
		} 
		
		if (dbg_flag) printf("Received %d bytes from %s\n", 
			recv_len, inet_ntoa(from_addr.sin_addr));
		if (dbg_flag) printf("The received command : %s\n", recv_str); 

		if(_strcmpi(recv_str, "find")==0)
		{
			sprintf_s(send_str, "%s:%d", DIR_ADDR_STR, DIR_PORT);
			if (dbg_flag) printf("find: To get the directory IP address\n");
		}
		else
		{
			strcpy_s(send_str, "Default: command str not recognized");
			if (dbg_flag) printf("%s\n", send_str);
		}
		if (dbg_flag) printf("Response : %s\n", send_str);
		if (dbg_flag) printf("Response length : %d\n\n", strlen(send_str));
		sendto(sock, send_str, strlen(send_str), 0, 
			(struct sockaddr *) &from_addr, sizeof(from_addr)); 
	}

	// clean-up operations for winsock
	// send a DROP MEMBERSHIP message via setsockopt
	if ((setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,/*(void*) &mc_req,*/
		(const char FAR*) &mc_req, sizeof(mc_req))) < 0) 
	{
		printf("setsockopt() failed.\n");
		exit(-1);
	}

	closesocket(sock); 

	WSACleanup();  /* Cleanup Winsock */

	return 0;
}

unsigned int __stdcall directory(void *args)
{
	if (dbg_flag) printf("Directory activated.\n\n");

	// Load Winsock 2.0 DLL
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) 
	{
		printf("WSAStartup() failed");
		exit(-1);
	} 
 
	// create socket
	SOCKET listen_sock;
	if ((listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) 
	{
		printf("Error at socket(): %ld\n", WSAGetLastError());
		WSACleanup();
		exit(-1);	
	}

	// prepare address structure
	struct sockaddr_in dir_addr;
	memset(&dir_addr, 0, sizeof(dir_addr));
	dir_addr.sin_family = AF_INET;
	dir_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	dir_addr.sin_port = htons(DIR_PORT);

	// bind and listen
	socket_bind_listen(listen_sock, &dir_addr, sizeof(dir_addr));

	// get keys and certificates from CA - these will be used in communication 
	// both with the service and the client
	dir_key_pair = generateRSAKeyPair(1024);
	const char * dir_csr = generateCSR(dir_key_pair);
	dir_cert = getCertificate(dir_csr);

	// start accepting connections
	//TODO add later - int req_proc_threads[MAX_REQ];
	struct sockaddr_in from_addr;
	int from_len = sizeof(from_addr);
	SOCKET accept_socket;
	unsigned int threadID;
	// loop until one of the threads below, handling the connections, 
	// terminates this directory thread with a signal
	while (1)
	{
		memset(&from_addr, 0, from_len);
		accept_socket = socket_accept(listen_sock, &from_addr, &from_len);

		// spawn a new thread to handle this accepted socket connection
		// pass it the accepted socket handle and the from_addr structure
		dir_request req;
		req.from_sock = accept_socket;
		req.from_addr = from_addr;
		_beginthreadex(NULL, 0, &handle_connection, &req, 0, &threadID);
		//TODO keep track of the threads working on requests
		// all these threads have to be exited before this dir thread can be terminated by a signal
		//req_proc_threads[REQ_CNT++] = threadID;
	}
	
	closesocket(listen_sock); 
	
	WSACleanup();  // Cleanup Winsock
	
	return 0;
}

unsigned int __stdcall handle_connection(void *args)
{
	struct dir_request req = *((struct dir_request*)args);
	const char * response;

	char * certificate, *enc_request, *signature;
	int enc_request_len, signature_len;
	char * request;
	int temp_len;

	// keep receiving and processing requests until the connection is closed
	while(1)
	{
		// 1. get the public key certificate from the other end (service/client)
		socket_recv(req.from_sock, &certificate, &temp_len);

		if (_strcmpi(certificate, "shutdown")==0) // the directory received a shutdown request
		{
			//NOTE - can just exit and close all the threads in this process
			//TODO somehow signal and terminate the directory thread which spawned 
			// this connection handling thread
		}

		// 2. send back the directory's public key certificate
		socket_send(req.from_sock, dir_cert, strlen(dir_cert));

		// 3. verify the certificate
		if (!verify_certificate(certificate))
		{
			printf("The certificate is not valid. Closing connection now.\n");
			// can also send terminate message to the other end if required
			break;
		}
		
		// 4. get the request and signature
		socket_recv(req.from_sock, &enc_request, &enc_request_len);
		socket_recv(req.from_sock, &signature, &signature_len);

		// 5. verify the signature
		const char * rec_hash_request = 
			recoverSignedData(certificate, signature, signature_len);
		CSHA1 sha1;
		sha1.Update((UINT_8*)enc_request, enc_request_len);
		sha1.Final();
		unsigned char * strReport = (unsigned char*) calloc(50, sizeof(unsigned char));
		sha1.GetHash(strReport);
		const char * calc_hash_request = (char*)strReport;
		if (strcmp(rec_hash_request, calc_hash_request) != 0)
		{
			printf("Signature validation failed.\nClosing connection now...\n");
			// can also send a terminate message to the other end
			break;
		}
		free(strReport);

		// 6. decrypt the encrypted request using the RSA key pair
		request = (char*)decryptData(dir_key_pair, enc_request, enc_request_len);

		// 7. process the request
		response = process_request(request);

		// 8. send back response
		socket_send(req.from_sock, response, strlen(response));
	}
	// close the accepted socket connection
	closesocket(req.from_sock);
	printf("Closed connection to %s:%d\n", 
		inet_ntoa(req.from_addr.sin_addr), 
		ntohs(req.from_addr.sin_port));

	return 0;
}

const char * process_request(char * strbuf)
{
	char * req_parts[MAX_REQ_PARTS];
	int num_parts = 0;
	char * context;
	char * tok;

	// split the request into parts
	req_parts[num_parts++] = strtok_s(strbuf, "|", &context);
	while ((tok=strtok_s(NULL, "|", &context)) != NULL)
	{
		req_parts[num_parts++] = tok;
	}

	// look for the command part
	char *name = NULL, *value = NULL, *command = NULL;
	for(int i=0; i<num_parts; i++)
	{
		name = strtok_s(req_parts[i], ":", &context);
		value = strtok_s(NULL, ":", &context);
		if (_strcmpi(name, "command")==0)
		{
			command = value;
			req_parts[i] = NULL;
			break;
		}
	}
	
	const char * response;
	if (command != NULL)
	{
		if (_strcmpi(command, "query")==0)
		{
			response = do_query_request(req_parts, num_parts);
		}
		else if(_strcmpi(command, "register")==0)
		{
			response = do_register_request(req_parts, num_parts);
		}
		else
		{
			response = "Unrecognized command found in the request";
		}
	}
	else
	{
		response = "No command was found in the request";
	}

	return response;
}

const char * do_query_request(char ** req_parts, int num_parts)
{
	char *context, *name, *value;
	char *req_svc_type = NULL;
	char *response = (char*)calloc(MAX_MSG_LEN, sizeof(char));

	// get the service type requested for
	for (int i=0; i<num_parts; i++)
	{
		if (req_parts[i]==NULL) continue; // command part was nulled in process_request
		name = strtok_s(req_parts[i], ":", &context);
		value = strtok_s(NULL, ":", &context);
		if (name != NULL && _strcmpi(name, "type")==0)
		{
			req_svc_type = value;
		}
	}
	if (req_svc_type == NULL)
	{
		return "'type' attribute is mandatory for a query request";
	}

	// get the service list for the requested service type
	list<CService> services = db_util.getServicesByType(req_svc_type);
	list<CService>::iterator svc_iter;
	list<CServiceAttribute>::iterator svc_attr_iter;

	if (services.empty())
	{
		sprintf_s(response, MAX_MSG_LEN, 
			"No service of the requested type:%s has registerd with this directory", 
			req_svc_type);
		return response;
	}

	// for now - return all the services in the list
	// in future - this might be the place to implement a strategy to return
	// the nearest service based on location
	for (svc_iter=services.begin(); svc_iter!=services.end(); svc_iter++)
	{
		strcat_s(response, MAX_MSG_LEN, "name:");
		strcat_s(response, MAX_MSG_LEN, (char*)(*svc_iter).m_name.c_str());
		strcat_s(response, MAX_MSG_LEN, "|port:");
		char temp_port[6];
		_itoa_s((*svc_iter).m_port, temp_port, 6, 10);
		strcat_s(response, MAX_MSG_LEN, temp_port);
		strcat_s(response, MAX_MSG_LEN, "|ip:");
		strcat_s(response, MAX_MSG_LEN, (char*)(*svc_iter).m_ip.c_str());
		// add attributes if any
		for (svc_attr_iter=(*svc_iter).m_attributes.begin(); 
			svc_attr_iter!=(*svc_iter).m_attributes.end(); 
			svc_attr_iter++)
		{
			strcat_s(response, MAX_MSG_LEN, "|");
			strcat_s(response, MAX_MSG_LEN, (char*)(*svc_attr_iter).m_name.c_str());
			strcat_s(response, MAX_MSG_LEN, ":");
			strcat_s(response, MAX_MSG_LEN, (char*)(*svc_attr_iter).m_value.c_str());
		}
		strcat_s(response, MAX_MSG_LEN, "]");
	}

	return response;
}

const char * do_register_request(char ** req_parts, int num_parts)
{
	char *response = (char*)calloc(MAX_MSG_LEN, sizeof(char));
	char *context, *name, *value;
	string empty = string("");
	CService service(empty, empty, 0);
	CServiceType type (empty, empty);

	for (int i=0; i<num_parts; i++)
	{
		if (req_parts[i]==NULL) continue; // command part was nulled in process_request
		name = strtok_s(req_parts[i], ":", &context);
		value = strtok_s(NULL, ":", &context);
		if (name != NULL && _strcmpi(name, "type")==0)
		{
			type.m_name = string(value);
		}
		else if (name != NULL && _strcmpi(name, "description")==0)
		{
			type.m_description = string(value);
		}
		else if (name != NULL && _strcmpi(name, "port")==0)
		{
			service.m_port = atoi(value);
		}
		else if (name != NULL && _strcmpi(name, "name")==0)
		{
			service.m_name = string(value);
		}
		else if (name != NULL && _strcmpi(name, "ip")==0)
		{
			service.m_ip = string(value);
		}
		else if (name != NULL) // everything else will be added as attributes of the service
		{
			service.addAttribute(CServiceAttribute(name,value));
		}
	}
	if (type.m_name.empty() || service.m_port == 0 || service.m_name.empty() || service.m_ip.empty())
	{
		sprintf_s(response, MAX_MSG_LEN, 
			"'type', 'port', 'name' and 'ip' attributes mandatory for a register request");
		return response;
	}

	// call the register service
	if (db_util.regService(type, service) == 0)
	{
		sprintf_s(response, MAX_MSG_LEN, "OK. Service registered successfully");
	}
	else
	{
		sprintf_s(response, MAX_MSG_LEN, "Directory register service utility did not complete successfully. Please check the directory for error details.");
	}
	return response;
}
