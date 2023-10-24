#include <cstdint>
#include <cstdlib>

#include <future>
#include <iostream>
#include <iterator>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <kademlia/endpoint.hpp>
#include <kademlia/session.hpp>
#include <kademlia/error.hpp>

#define SERVER_SOCK_FILE "server.sock" 

// SERVER PROCESS FOR SOCKET COMMUNICATION WITH CLIENT.CPP
namespace k = kademlia;

namespace {

const char HELP[] =
"put <KEY> <VALUE>\n\tSave <VALUE> as <KEY>\n\n"
"get <KEY>\n\tGet value associated with <KEY>\n\n"
"help\n\tPrint this message\n\n";

int fd;
struct sockaddr_un addr;
int ret;
char *buff;
struct sockaddr_un from;
int ok = 1;
int len;
socklen_t fromlen = sizeof(from);

std::vector< std::string >
split( std::string const& line )
{
    std::istringstream in{ line };

    using iterator = std::istream_iterator< std::string >;
    return std::vector< std::string >{ iterator{ in }, iterator{} };
}

void
load( k::session & session
    , std::string const& key )
{
    auto on_load = [ key ] ( std::error_code const& error
                           , k::session::data_type const& data )
    {
        const char* resp;
        if ( error )
            resp = std::string{"ERROR"}.c_str();
        else
        {
            std::string const& str{ data.begin(), data.end() };
            resp = str.c_str();
        }
        ret = sendto(fd, resp, strlen(resp)+1, 0, (struct sockaddr *)&from, fromlen);
        if (ret < 0) {
            perror("sendto");
        }
    };

    session.async_load( key, std::move( on_load ) );
}

void
save( k::session & session
    , std::string const& key
    , std::string const& value )
{
    auto on_save = [ key ] ( std::error_code const& error )
    {
        const char* resp = error ? std::string{"ERROR"}.c_str() : std::string{"SUCCESS"}.c_str();
        ret = sendto(fd, resp, strlen(resp)+1, 0, (struct sockaddr *)&from, fromlen);
        if (ret < 0) {
            perror("sendto");
        }
    };

    session.async_save( key, value, std::move( on_save ) );

}

void
print_interactive_help
        ( void )
{
    std::cout << HELP << std::flush;
}

} // anonymous namespace

enum class Action {
    GET, PUT
};

const int DEFAULT_BUFFER = 1024;

int main(int argc, char** argv ) {
    // Check command line arguments count
    if ( argc != 3 )
    {
        std::cerr << "usage: " << argv[0] << " <PORT> <INITIAL_PEER>" << std::endl;
        return EXIT_FAILURE;
    }

    // Parse command line arguments
    std::uint16_t const port = std::atoi( argv[1] );
    k::endpoint initial_peer;
    std::istringstream{ argv[2] } >> initial_peer;

    // Create the session
    k::session session{ initial_peer
                      , k::endpoint{ "0.0.0.0", port }
                      , k::endpoint{ "::", port } };

    // Start the main loop thread
    auto main_loop = std::async( std::launch::async
                               , &k::session::run, &session );


    buff = new char[DEFAULT_BUFFER];

	if ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		ok = 0;
	}

	if (ok) {
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strcpy(addr.sun_path, SERVER_SOCK_FILE);
		unlink(SERVER_SOCK_FILE);
		if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			perror("bind");
			ok = 0;
		}
	}

    bool isPut = false;
    std::string key;
    int size = DEFAULT_BUFFER;
	while ((len = recvfrom(fd, buff, size, 0, (struct sockaddr *)&from, &fromlen)) > 0) {
        std::string buff_str = std::string{buff};
        if (isPut) {
            save( session, key, buff_str );
            isPut = false;
        } else {
            auto const tokens = split(buff_str);
            if ( tokens.empty() )
                continue;

            if ( tokens[0] == "get" )
            {
                if ( tokens.size() != 2 ) {
                    break;
                } else {
                    load( session, tokens[1] );
                    isPut = false;
                }
            }
            else if ( tokens[0] == "put" )
            {
                if ( tokens.size() != 3 ) {
                    break;
                } else {
                    size = stoi(tokens[2]);
                    buff = new char[size];
                    key = move(tokens[1]);
                    isPut = true;
                    continue;
                }
            }
            else
                break;
        }
	}
    
    char* bye_msg = (char *)"closing socket\0";
    ret = sendto(fd, bye_msg, strlen(bye_msg)+1, 0, (struct sockaddr *)&from, fromlen);
    if (ret < 0) {
        perror("sendto");
    }

    // Stop the main loop thread
    session.abort();

    // Wait for the main loop thread termination
    auto failure = main_loop.get();
    if ( failure != k::RUN_ABORTED ) {
        std::cerr << failure.message() << std::endl;
    }
	
	if (fd >= 0) {
		close(fd);
	}

	return 0;
}
