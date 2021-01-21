
# Overview of Network

This abstracts Berkley sockets to an event based, managed resource.

  - [TCP Server](#tcp-server)
  - [TCP Client](#tcp-client)
  - [UDP Server/Client](#udp)
  - HTTP Client
  - WebSocket Server/HTTP Server

## First

Enable networking; internally this sets up network tracking structures begins network threads, and
tests for network system for functionality.

``` C
	if( !NetworkStart() )
        	printf( "Network Failed to initialize\n" );
```

or

``` C

void InitNetwork() {
	int min_clients = 16;
	int extra_data_length = 16;
	if( !NetworWait( 0, min_clients, extra_data_length ) )
        	printf( "Network failed to initialized.\n" );
}
```

## Network Addresses

Network addresses are abstracted to a type `SOCKADDDR*` which is generally a direct
wrapper of the host platforms native network structure.  It is preceeded by its own size,
and the address MUST be deallocated with `ReleaseAddress()` when address you have created are no longer needed. 
(`SOCKADDR`s which are allocated by the library are tracked and released by the library).

`CreateSockAddress` should be used to create addresses.  It takes a string defining the IP and optional port specification;
if the port is not specified in the text, the port number is specified as a secondary number. Name can be
an IPv4 or IPv6 number or a hostname, which is looked up using standard network name resolution.

``` C
	SOCKADDR* addr1 = CreateSockAddress( "host.address:123", 0 );
	SOCKADDR* addr2 = CreateSockAddress( "1.1.1.1", 10503 );
	SOCKADDR* addr3 = CreateSockAddress( "::0", 5054 );      // all addresses port 5054
```

## Closing Sockets

Use RemoveClient to close a socket; whether TCP client or server or UDP.  There are more advanced
versions of this close which allows controlling 'linger' and callback nofication dispatch.  This 
generally will immediately do a `shutdown()` to prevent additional sends, and will linger until all
data from the remote side has been read.

``` C
	void doClose( PCLIENT client ) {
		RemoveClient(client);
        }
```

## TCP Server

Creating a tcp server after starting the network.

Most TCP listener creation methods take a callback defined by the application
which receives a reference to the original server socket that got the connection
and the newly accepted socket.  This callback should be used to initialize anything
the application needs in relation to a new connection.

``` C
	SOCKADDR *address = CreateSockAddress( argv[1], 8080 );
	PCLIENT server = OpenTCPListenerAddrEx( address, connected );
```

This is a simple example connection callback.  The new client does inherit
read, close and write callbacks from the server automatically; the listener
socket itself never gets any of those events;   This demonstrates setting
the close and read callback on the newly accepted client.

Various information about the socket can be set and retrieved using `GetNetworkLong()` and `SetNetworkLong()` [more](#Network Information).




``` C
static void connected( PCLIENT server, PCLIENT newClient) {
	SetNetworkReadComplete( newClient, received );
        SetNetworkCloseCallback( newClient, disconnected );
        
        struct myAppData {
        	void *buffer;
        } *data = malloc( sizeof( *data ) );
        SetNetworkLong( newClient, 0, data );
}

```



```
static void received( PCLIENT client, POINTER buffer, size_t length ) {
	uintptr_t userData = GetNetworkLong( client, 0 );
	struct myAppData *data = (struct myAppData *)userData;
	if( !buffer ) {
        	// the first time this is called, buffer is NULL and length is 0.
                data->buffer = malloc( 4096 );
                
                
        } else {
        	// handle network message...
        }
        ReadTCP( client, data->buffer, 4096 );
}
```

This is an example close callback

```
static void disconnected( PCLIENT client ) {
	// release any application data associated with the socket.
	uintptr_t userData = GetNetworkLong( client, 0 );
	struct myAppData *data = (struct myAppData *)userData;
        free( data->buffer );
        free( data );
}
```

## Send TCP Data

Sending data is fairly straight forward.  The basic behavior buffers data that cannot be immediately sent
internally until it will be sent.  Advanced methods allow passing buffers that are not duplicated, but requires
additionally handling the 'write complete' callback to handle notification that the buffer is no longer in use.

``` C
	// data is a const void*
        // length is the length to send in bytes.
	SendTCP( client, data, length );
```


## TCP Client

There are a variety of methods which can be used to create a connection to a server; depending on specific requirements.

This is the most common, basic usage.

``` C
	SOCKADDR* addr = CreateSockAddress( "example.com:80", 0 );
	OpenTCPClientAddrExx( addr, readComplete, closeCallback, NULL, NULL );
```

``` C
static void readComplete(PCLIENT pc, POINTER buffer, size_t length) {
	// first read passed null
        if( !buffer ) {
        	buffer = malloc( 4096 );
        } else {
        	// handle received buffer of length N
        }
        ReadTCP( pc, buffer, 4096 );
}
```

``` C
static void closeCallback(PCLIENT pc) {
	// socket has been closed.
}
```

# UDP Sockets

## Open a UDP Socket

UDP Sockets generally don't get a close event; although it can happen from losing a network interface.

```
	PCLIENT udpSocket = ServeUDP( "address.com", port
        	, udpReadCallback
        	, NULL /*closeCallback*/ 
                );
                
	// queue the first read.
        ReadUDP( udpSocket, buffer, 4096 );

```

The UDP Read callback receives a reference of the source address of the packet.

```
void udpReadComplete( PCLIENT client, POINTER buffer, size_t length, SOCKADDR *from ){
	// handle message.

        ReadUDP( udpSocket, buffer, 4096 );
	
}
```


## Send UDP

```
	// buf is a void const*
        // length is the length of the data in bytes.
	SendUDP( socket, buf, length );
```




### Enable TLS On Server

TLS can be enabled on an opened server.  This replaces the initial open callback notification
with TLS negotiation using the specified certificate.

```
	// you will need certificate information and optional keypair to use
	LOGICAL result = ssl_BeginServer( server
        		, CPOINTER cert, size_t certlen
                        , CPOINTER keypair, size_t keylen
                        , CPOINTER keypass, size_t keypasslen);
                        
        // this version is able to compare hostnames for validiity
 	LOGICAL result = ssl_BeginServer_v2( server
			, NULL, 0 /*, CPOINTER cert, size_t certlen*/
			, NULL, 0 /*, CPOINTER keypair, size_t keylen*/
			, NULL, 0 /*, CPOINTER keypass, size_t keypasslen*/
			, "server.com;server2.com" /*char* hosts*/
	);
```

### Is SSL Enabled?

This can also be used in the connect callback, a client socket will either be
secure or not, an accepted client may fail SSL negotiation, and be reported as 
insecure, allowing the application to alternatively accept the client.

A secure socket needs to use a different function to send data; `ssl_Send()` instead of `SendTCP()`.

```
		if( ssl_IsClientSecure( server ) ) {
                	// yes, yes it is.
                }
```

### SSL Host Requested

SSL Connections may include a requested host during negotation; this allows
a server to multi-home multiple domains.

``` C
	ssl_GetRequestedHostName( client );
```        





## Extra

### Is network Started?

```
	if( NetworkAlive() ) {
        	printf( "Yes" );
        } else {
        	printf( "No" );
        }
```


### Shutdown Networking

This is not required, and is generally handled by stopping the program.

NetworkQuit can be called to shutdown networking threads and release allocated resources.
This function returns 0 if networking is not started, and not zero (-1) when the network has been shutdown,
including all threads stopped; may block forever if a network thread calls this method.

``` C
	NetworkQuit();
```

### Get Network Address Data

Sometimes you will want to get and set network addresses in a direct binary format, or
get the numeric (non-text) values of an address.

``` C
	SOCKADDR *addr = CreateSockAddress( "example.com", 0 );
        uint8_t *data;
        size_t size;
	GetNetworkAddressBinary( addr, &data, &size );
```

``` C
	int32_t dwIP;
        uint16_t port;
        GetAddressParts( addr, &dwIP, &port );
```

  - CompareAddress (CompareAddressEx)
  - IsThisAddressMe
  - `PLIST list =  GetLocalAddresses()`
  


For development purposes you may wish to allow otherwise invalid certificates.
This option should not be used in final code.

```
	ssl_SetIgnoreVerification( server );
```

### TCP Options

  - SetTCPNoDelay( client, TRUE/FALSE );
  - SetClientKeepAlive( client, TRUE/FALSE );
  
### UDP/TCP Options  
  - SetSocketReuseAddress
  - SetSocketReusePort



# Extra Utilities

## Ping

```
	PVARTEXT pvtResult = VarTextCreate(); // a sort of string builder/dynamic string buffer
	DoPing( "address"
        	, 255 /* maxTTL - can be stepped for 'traceroute' */
		, 500 /* milliseconds to wait for reply */
		, 4 /* count of attempts */
                , pvtResult
                , TRUE /* do reverse DNS lookup of addresses */
                , resultCallback  // per-hop callback for custom handling
                );
        
        VarTextDestroy( &pvtResult );
```


## Whois Registry Query

Once upon a time there was a domain whois query function that worked...
needs the root servers updated.
