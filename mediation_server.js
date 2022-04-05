var udp = require('dgram');
var tcp = require('net');
const { Buffer } = require('buffer');

var sockets = [];
var udp_connection_info = [];
//10 second default timeout
var timeout = 10;

// TCP SERVER

var tcp_server = tcp.createServer(function(socket){
    var buf = Buffer.alloc(1024);
    var bufLength = 0;
    buf.writeUInt8(0, 0);
    bufLength += 1;
    buf.write("Connected pog", bufLength);

    socket.on('close', function(){
        console.log("Someone disconnected");
        for(let i=0; i<sockets.length; i++){
            if(sockets[i][0] == socket){
                for(let f=0; f<udp_connection_info.length; f++){
                    if(udp_connection_info[f][0] == sockets[i][1]){
                        udp_connection_info.splice(f, 1);
                        console.log("udp splice worked???");
                    }
                }
                sockets.splice(i, 1);
                console.log("it worked???");
                console.log(sockets.length);
            }
        }
    });

    socket.on('error', function(err){
        console.log('idk socket');
        console.log(err);
    });

    socket.write(buf);
    socket.pipe(socket);
});

// print when server begins listening
tcp_server.on('listening', function(){
    var address = tcp_server.address();
    var port = address.port;
    var family = address.family;
    var ipaddr = address.address;
    console.log(`Server is listening at port ${port}`);
    console.log(`Server IP: ${ipaddr}`);
    console.log(`Server is IP4/IP6: ${family}`);
});

// print on connection
tcp_server.on('connection', function(socket){
    console.log(`Received connection from ${socket.remoteAddress}:${socket.remotePort}`);
    sockets.push([socket, socket.remoteAddress, socket.remotePort, timeout]);
    console.log(sockets);
});

tcp_server.on('error', function(err){
    console.log('move along, no error to see here');
    console.log(err);
});

tcp_server.listen(6510, "0.0.0.0");

// UDP SERVER

// create the udp server
var udp_server = udp.createSocket({type: 'udp4', reuseAddr: true});

// handle errors
udp_server.on('error', function(err){
    console.log(`Error: ${err}`);
    udp_server.close();
});

// print on new udp packets
udp_server.on('message', function(msg, info){
    console.log(`Data received from client: ${msg}`);
    console.log(`Received ${msg.length} bytes from ${info.address}:${info.port}`);

    for(let i=0; i<sockets.length; i++){
        if(sockets[i][1] == info.address){
            sockets[i][3] = timeout;
        }
    }

    var add_ip = true;

    for(let i=0; i<udp_connection_info.length; i++){
        if(udp_connection_info[i][0] == info.address){
            add_ip = false;
        }
    }

    if(add_ip){
        udp_connection_info.push([info.address, info.port]);
    }

    var contains_intended_ip = false;
    var intended_ip = "";
    var intended_port = "";
    var str = String(msg);

    for(let i=0; i<sockets.length; i++){
        if(str.includes(sockets[i][1])){
            contains_intended_ip = true;
            intended_ip = sockets[i][1];
            intended_port = sockets[i][2];
            for(let d=0; d<udp_connection_info.length; d++){
                if(udp_connection_info[d][0] == intended_ip){
                    intended_port = udp_connection_info[d][1];
                }
            }
        }
    }

    if(!contains_intended_ip){
        intended_ip = info.address;
        intended_port = info.port.toString();
    } else {
        var buf = Buffer.from(`${info.address}:${info.port}:clientreq`);

        udp_server.send(buf, intended_port, intended_ip, function(err){
            if(err){
                udp_server.close();
            } else {
                console.log('Data sent to server for client connection');
            }
        });
        
        var buf = Buffer.from(`${intended_ip}:${intended_port}`);

        udp_server.send(buf, info.port, info.address, function(err){
            if(err){
                udp_server.close();
            } else {
                console.log('Data sent to client for server connection');
            }
        });
    }

    var buf = Buffer.from(`${intended_ip}:${intended_port}`);

    // sending data
    udp_server.send(buf, info.port, info.address, function(err){
        if(err){
            udp_server.close();
        } else {
            console.log('Data sent to client');
        }
    });
});

// print when server begins listening
udp_server.on('listening', function(){
    var address = udp_server.address();
    var port = address.port;
    var family = address.family;
    var ipaddr = address.address;
    console.log(`Server is listening at port ${port}`);
    console.log(`Server IP: ${ipaddr}`);
    console.log(`Server is IP4/IP6: ${family}`);
});

// print when server closes
udp_server.on('close', function(){
    console.log("Socket closed");
});

udp_server.bind(6510);

// check every second to see if a client has wrongly disconnected
setInterval(function timeout_loop(){
    console.log(sockets.length);
    if(sockets.length > 0){
        for(let socket=0; socket<sockets.length; socket++){
            console.log(sockets[socket][3]);
            if(sockets[socket][3] > 0){
                sockets[socket][3] = sockets[socket][3] - 1;
                console.log(sockets[socket][3]);
            }  
            if(sockets[socket][3] == 0){
                for(let udp_socket=0; udp_socket<udp_connection_info.length; udp_socket++){
                    if(udp_connection_info[udp_socket][0] == sockets[socket][1]){
                        udp_connection_info.splice(udp_socket, 1);
                    }
                }
                sockets.splice(socket, 1);
                console.log("timed out");
            }
        }
    }
}, 1000);
