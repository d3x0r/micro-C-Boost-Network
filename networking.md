
# Overview of Network

This abstracts Berkley sockets to an event based, managed resource.

  - [Network Addresses](#network-addresses)
  - [TCP Server](#tcp-server)
  - [TCP Client](#tcp-client)
  - [UDP Server/Client](#udp-sockets)
  - [WebSocket Server/HTTP Server](#websocket-stuff)
  - [HTTP Client](#http-client)



## First Steps

Enable networking; internally this sets up network tracking structures begins network threads, and
tests for network system for functionality. This will start with a default of 16 extra client 'words' and 16 
sockets allocated.

``` C
	if( !NetworkStart() )
		printf( "Network Failed to initialize\n" );
```

Additional control over initialization is provided with the `NetworkWait` function.  For legacy reasons there
is a first parameter which is unused, and should be set to 0.  The second parameter is the minimum number of clients to allocate.
The third parameter is the number of extra network data words to provide.  Sockets rarely need more then one extra 'word'.  Words of 
user data are `uintptr_t` which may be a pointer value or any integer value.  The extra user data slots are to allow
the application to associate data with the socket on open or connect which can be used in read or close callbacks; for example
allocation of data buffers to read into and the final release of those buffers.

``` C

void InitNetwork() {
	int min_clients = 16;
	int extra_data_length = 16;
	if( !NetworWait( 0, min_clients, extra_data_length ) )
        	printf( "Network failed to initialized.\n" );
}
```
## Network User Data

`GetNetworkLong()` and `SetNetworkLong()` can be used to associate application data with a socket.

### SetNetworkLong( socket, word, data )

The `word` parameter is the index of the value, it must be between 0 and `extra_data_length` (in the above code).  
Any request for a higher word will return always. 

The `data` parameter is a uintptr_t to assign to the user data slot specified by word.

### GetNetworkLong( socket, word )

The `word` parameter is the index of the value, it must be between 0 and `extra_data_length` (in the above code).  
Any request for a higher word will return always. 

Some socket internals are exposed with negative word indexes(More later).

return value is a uintptr_t.

## Network Addresses

Network addresses are abstracted to a type `SOCKADDDR*` which is generally a direct
wrapper of the host platforms native network structure.  It is preceeded by its own size,
and the address MUST be deallocated with `ReleaseAddress()` when address you have created are no longer needed. 
(`SOCKADDR`s which are allocated by the library are tracked and released by the library).

`CreateSockAddress` should be used to create addresses.  It takes a string defining the IP and optional port specification;
if the port is not specified in the text, the port number is specified as a secondary number. Name can be
an IPv4 or IPv6 number or a hostname, which is looked up using standard network name resolution.

SOCKADDR* also maintains a text version of the name internally, so the original parameters of address may
be known; for example if the socket is created with "domain.com" that will be resolved into a numeric address
which is the primary data value of a SOCKADDR; however, `GetAddrName( SOCKADDR* )` can be used to get that name, where
`GetAddrString( SOCKADDR*)` returns a text representation of the numeric value of the address.

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

#### Server Connect Callback

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

#### Read Complete Callback

This is an example read complete routine.  The application would fill in more code
in `//handle network message...`

``` C
static void received( PCLIENT client, POINTER buffer, size_t length ) {
	// get associated user data.
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

#### Close Callback

This is an example close callback

``` C
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


## Websocket Server

Create a websocket server.

``` C
	PCLIENT server = WebSocketCreate( "::0:8080"  // CTEXTSTR server_url
	                                , on open     // web_socket_opened on_open
	                                , on_message  // web_socket_event on_event
	                                , on_close    // web_socket_closed on_closed
	                                , on_error    // web_socket_error on_error
	                                , 0           // uintptr_t psv
	                                );
```

The open event is called whenever a new socket has successfully negotiated a websocket connection.
The PCLIENT has additional methods that may work on it.  The return value of the open callback is passed
to subsequent message, close and error callbacks.

``` C 

static uintptr_t on_open( PCLIENT pc, uintptr_t psv ){
	// new socket accepted.  psv is parameer passed from create.

	// return a per-socket user data value.
	return 0;  // this value is passed to on_message, on_close and on_error callbacks.
}
```

The close event is sent when the client issues a .close(); or when a network connection fails.

``` C
void on_close( PCLIENT pc, uintptr_t psv, int code, const char *reason ){
	// websocket closed; recieved code and reason from shutdown (1006 otherwise)
}
```

The message callback is called with a buffer allocated by the network layer, with a completed websocket packet.

```
void on_message( PCLIENT pc, uintptr_t psv, LOGICAL binary, CPOINTER buffer, size_t msglen ){
	// if binary, buffer IS an array of bytes
   // if text, buffer IS a utf8 string
   // psv is value returned from 'on_open'
}
```

The error callback is called when there is a protocol error which is causing a close.  The next callback will be a close event.

``` C
void on_error( PCLIENT pc, uintptr_t psv, int error ){
	// an error occured; 
}
```

## Websocket Client

Opening a websocket takes a URL as the address.  It will select SSL as suggested by the protocol.
Protocols can be a simple string or JSON array of strings, as examples: `"protocol"`, or `"['protocol','another','third']"`.

```
	PCLIENT client = WebSocketOpen( "ws://address.com:1234/url"   //CTEXTSTR address
                               	, 0           // enum WebSocketOptions options
                                 , on_open     // web_socket_opened
                                 , on_message  // web_socket_event
                                 , on_close    // web_socket_closed
                                 , on_error    // web_socket_error
                                 , 0           // uintptr_t psv
                                 , "testProto" // const char *protocols );
```

The same open, message, close and error callbacks are used for client sockets.

### WebSocket Accept callback

Finer grain control of the accept chain is available.  Registering an 'on accept' callback allows
inspection of the connection before the websocket protocol negotiation starts; this can be used to enable
SSL on the fly for a connection.

```
	PCLIENT pc; // some open socket...

	SetWebSocketAcceptCallback( PCLIENT pc, on_accept );
```

An example on_accept callback.

``` C
LOGICAL on_accept(PCLIENT pc, uintptr_t psv, const char *protocols, const char *resource, char **protocolsAccepted){
	// pc is the network connection beign accepted
   // psv is the server Create user data parameter
	// protocols are the requested protocols
   // resource is the URL path requested
   // protocolsAccepted sets the repsonse for protocols; otherwise what is requested is copied in reply.

	return TRUE; /*to continue or FALSE to reject */
}
```

## HTTP Fallback for websockets...

A websocket server is also mostly a HTTP server, so if the websocket protocol
is not negotiated, can register a handler for non websocket connections.

``` C
	// set a callback to handle just an arbitrary request	
	SetWebSocketHttpCallback( PCLIENT pc
	                        , on_http_request //web_socket_http_request callback 
                           );
	// set a callback when the HTTP connection is closed.
	SetWebSocketHttpCloseCallback( PCLIENT pc
	                             , web_socket_http_close callback
	                             );
```

This is an example request handler...
The HTTP State of the request is available using `GetWebSocketHttpState`.  Which then has a bunch of
accessor methods to get the resource path, headers, and content of an HTTP message (either request and response).

``` C

uintptr_t on_http_request(PCLIENT pc, uintptr_t psv){
	struct HttpState *pHttpState = GetWebSocketHttpState( pc );


/* Gets the specific result code at the header of the packet -
   http 2.0 OK sort of thing.                                  */
PTEXT HTTPAPI GetHttpResponce( HTTPState pHttpState );


/* Get the method of the request in ht e http state. */
PTEXT HTTPAPI GetHttpMethod( struct HttpState *pHttpState );


/*Get the value of a HTTP header field, by name
   Parameters
	pHttpState: the state to get the header field from.
	name: name of the field to get (checked case insensitive)
*/
PTEXT HTTPAPI GetHTTPField( HTTPState pHttpState, CTEXTSTR name );


/* Gets the specific request code at the header of the packet -
   http 2.0 OK sort of thing.                                  */
PTEXT HTTPAPI GetHttpRequest( HTTPState pHttpState );


/* \Returns the body of the HTTP packet (the part of data
   specified by content-length or by termination of the
   connection(? think I didn't implement that right)      */
PTEXT HTTPAPI GetHttpContent( HTTPState pHttpState );


/* \Returns the resource path/name of the HTTP packet (the part of data
   specified by content-length or by termination of the
   connection(? think I didn't implement that right)      */
PTEXT HTTPAPI GetHttpResource( HTTPState pHttpState );


/* Returns a list of fields that were included in a request header.
   members of the list are of type struct HttpField.
   see also: ProcessHttpFields and ProcessCGIFields
*/
PLIST HTTPAPI GetHttpHeaderFields( HTTPState pHttpState );
int HTTPAPI GetHttpVersion( HTTPState pHttpState );



/* Enumerates the various http header fields by passing them
   each sequentially to the specified callback.
   Parameters
   pHttpState :  _nt_
   _nt_ :        _nt_
   psv :         _nt_                                        */
void HTTPAPI ProcessCGIFields( HTTPState pHttpState, void (CPROC*f)( uintptr_t psv, PTEXT name, PTEXT value ), uintptr_t psv );


 /* Enumerates the various http header fields by passing them
   each sequentially to the specified callback.
   Parameters
   pHttpState :  _nt_
   _nt_ :        _nt_
   psv :         _nt_                                        */
void HTTPAPI ProcessHttpFields( HTTPState pHttpState, void (CPROC*f)( uintptr_t psv, PTEXT name, PTEXT value ), uintptr_t psv );


/* Resets a processing state, so it can start collecting the
   next state. After a ProcessHttp results with true, this
   should be called after processing the packet content.
   Parameters
   pHttpState :  state to reset for next read...             */
void HTTPAPI EndHttp( HTTPState pHttpState );


/* reply message - 200/OK with this body, sent as Content-Type that was requested */
void HTTPAPI SendHttpMessage( HTTPState pHttpState, PCLIENT pc, PTEXT body );


/* generate response message, specifies the numeric (200), the text (OK), the content type field value, and the body to send */
void HTTPAPI SendHttpResponse ( HTTPState pHttpState, PCLIENT pc, int numeric, CTEXTSTR text, CTEXTSTR content_type, PTEXT body );

```

An example HTTP close callback; allows releasing any data specified.


``` C
void on_http_close(PCLIENT pc, uintptr_t psv){
	// called at close; gets value returned from on_http_request callback.
}
````

#### Websocket data progress callback

Sometimes with very long messages, it might be nice to know how much of the message the network
has been received so far.  Any time there is a callback set, and the websocket layer completes a fragment
of a larger packet, the total collected length is posted to the callback.

``` C
SetWebSocketDataCompletion( client, on_completion );
```

Example completion callback.

``` C
typedef void (*web_socket_completion)( PCLIENT pc, uintptr_t psv, int binary, int bytesRead );

void on_completion( PCLIENT pc, uintptr_t psv, int binary, int bytesRead ){
		
}

```

### Misc Websocket Utilities

Websocket protocol itself supports a symmetric ping operation.
Sometimes per-socket callback overrides may be useful.

``` C
// This enables a keepalive ping on the websocket.
WebSocketEnableAutoPing( PCLIENT websock, uint32_t delay );
// this sends a ping on a websocket.
WebSocketPing( PCLIENT websock, uint32_t timeout );

// these methods can be used to manually set methods instead per socket\
SetWebSocketReadCallback( PCLIENT pc, web_socket_event callback );
SetWebSocketCloseCallback( PCLIENT pc, web_socket_closed callback );
SetWebSocketErrorCallback( PCLIENT pc, web_socket_error callback );
```


### Enable TLS On TCP Server

TLS can be enabled on an opened server.  This replaces the initial open callback notification
with TLS negotiation using the specified certificate.

``` C
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

### 

`ssl_BeginClientSession()` is used to initiate TLS negotiations on the client side.  
It is passed optional keypair, keypassword, and additional certificate chain.
It returns TRUE/FALSE for success/failure.

``` C
	PCLIENT pc = OpenTCPClientAddr( "somewhere.com", 1234, NULL, NULL, NULL );
	if( ssl_BeginClientSession )( pc
	                            , NULL  // CPOINTER keypair
				    , 0     // size_t keylen
				    , NULL  // CPOINTER keypass
				    , 0     // size_t keypasslen
				    , NULL  // CPOINTER rootCert
				    , 0     // size_t rootCertLen 
				    ) ) {
		printf( "Success..." );
	}
```

### Is SSL Enabled?

This can also be used in the connect callback, a client socket will either be
secure or not, an accepted client may fail SSL negotiation, and be reported as 
insecure, allowing the application to alternatively accept the client.

A secure socket needs to use a different function to send data; `ssl_Send()` instead of `SendTCP()`.

``` C
		if( ssl_IsClientSecure( socket ) ) {
                	// yes, yes it is.
			ssl_Send( socket, buffer, length );
                } else {
			SendTCP( socket, buffer, length );
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

``` C
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

### Internal Socket information from GetNetworkLong
 GNL_IP      = (-1),
 /* Gets the IP of the remote side of the connection, if
    applicable. UDP Sockets don't have a bound destination. */
 GNL_PORT    = (-4),
 /* Gets the port at the remote side of the connection that is
    being sent to.                                             */
 GNL_MYIP    = (-3),
 /* Gets the 4 byte IPv4 address that is what I am using on my
    side. After a socket has sent, it will have a set source IP
    under windows.                                              */
 GNL_MYPORT  = (-2),
 /* Gets the 16 bit port of the TCP or UDP connection that you
    are sending from locally.                                  */
 GNL_MAC_LOW = (-5),
 GNL_MAC_HIGH= (-6),
 GNL_REMOTE_ADDRESS = (-7),
 GNL_LOCAL_ADDRESS = (-8),




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
