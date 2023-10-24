#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>


#define CLIENT_SOCK_FILE "client.sock" 
#define SERVER_SOCK_FILE "server.sock" 

// CLIENT PROCESS FOR SOCKET COMMUNICATION WITH CLI_SOCK.CPP
int main() {
	int fd;
	struct sockaddr_un addr;
	int ret;
	char buff[8192];
	struct sockaddr_un from;
	int ok = 1;
	int len;

	if ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		ok = 0;
	}

	if (ok) {
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strcpy(addr.sun_path, CLIENT_SOCK_FILE);
		unlink(CLIENT_SOCK_FILE);
		if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			perror("bind");
			ok = 0;
		}
	}

	if (ok) {
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strcpy(addr.sun_path, SERVER_SOCK_FILE);
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
			perror("connect");
			ok = 0;
		}
	}   
    // if (ok) {
	// 	strcpy (buff, "get key1");
	// 	if (send(fd, buff, strlen(buff)+1, 0) == -1) {
	// 		perror("send");
	// 		ok = 0;
	// 	}
	// 	printf ("sent command\n");
	// }

	if (ok) {
		strcpy (buff, "put key2 6"); // the 6 must include the null char
		if (send(fd, buff, strlen(buff)+1, 0) == -1) {
			perror("send");
			ok = 0;
		}

		strcpy (buff, "hello");
		if (send(fd, buff, strlen(buff)+1, 0) == -1) {
			perror("send");
			ok = 0;
		}
		printf ("sent command\n");
	}

	if (ok) {
		if ((len = recv(fd, buff, 8192, 0)) < 0) {
			perror("recv");
			ok = 0;
		}
		printf ("receive %d %s\n", len, buff);
	}

	if (fd >= 0) {
		close(fd);
	}

	unlink (CLIENT_SOCK_FILE);
	return 0;
}