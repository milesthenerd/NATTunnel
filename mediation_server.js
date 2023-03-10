var udp = require('dgram');
var tcp = require('net');
const { Buffer } = require('buffer');

const nat_types = {
    Unknown: -1,
    DirectMapping: 0,
    Restricted: 1,
    Symmetric: 2
};

const msg_types = {
    Connected: 0,
    NATTypeRequest: 1,
    NATTestBegin: 2,
    NATTest: 3,
    NATTypeResponse: 4
};

var sockets = [];
var udp_connection_info = [];
//10 second default timeout
var timeout = 10; 

// TCP SERVER
var tcp_server = tcp.createServer(function(socket){
    socket.on('data', function(data){
        let message = JSON.parse(data);
        switch(message.ID){
            case msg_types.NATTypeRequest:
                for(let i=0; i<sockets.length; i++){
                    if(sockets[i][0] == socket){
                        sockets[i][5] = message.LocalPort;
                    }
                }
                socket.write(Buffer.from(JSON.stringify({"ID": msg_types.NATTestBegin})));
            break;
        }
    });

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

    socket.write(Buffer.from(JSON.stringify({"ID": msg_types.Connected})));
    
    //socket.pipe(socket);
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
    sockets.push([socket, socket.remoteAddress, socket.remotePort, timeout, -1, 0, 0, 0]);
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

var udp_nat_test_server = udp.createSocket({type: 'udp4', reuseAddr: true});

// handle errors
udp_nat_test_server.on('error', function(err){
    console.log(`Error: ${err}`);
    udp_nat_test_server.close();
});

// print on new udp packets
udp_nat_test_server.on('message', function(msg, info){
    console.log(`nat test 1 from ${info.address}:${info.port}`);
    for(let i=0; i<sockets.length; i++){
        if(sockets[i][1] == info.address){
            let message = JSON.parse(msg);
            switch(message.ID){
                case msg_types.NATTest:
                    sockets[i][6] = info.port;
                    check_nat_type(sockets[i][0], sockets[i][5], sockets[i][6], sockets[i][7]);
                break;
            }
        }
    }
});

// print when server begins listening
udp_nat_test_server.on('listening', function(){
    var address = udp_nat_test_server.address();
    var port = address.port;
    console.log(`NAT test 1 is listening at port ${port}`);
});

// print when server closes
udp_nat_test_server.on('close', function(){
    console.log("Socket closed");
});

udp_nat_test_server.bind(6511);

var udp_nat_test_server_2 = udp.createSocket({type: 'udp4', reuseAddr: true});

// handle errors
udp_nat_test_server_2.on('error', function(err){
    console.log(`Error: ${err}`);
    udp_nat_test_server_2.close();
});

// print on new udp packets
udp_nat_test_server_2.on('message', function(msg, info){
    console.log(`nat test 2 from ${info.address}:${info.port}`);
    for(let i=0; i<sockets.length; i++){
        if(sockets[i][1] == info.address){
            let message = JSON.parse(msg);
            switch(message.ID){
                case msg_types.NATTest:
                    sockets[i][7] = info.port;
                    check_nat_type(sockets[i][0], sockets[i][5], sockets[i][6], sockets[i][7]);
                break;
            }
        }
    }
});

// print when server begins listening
udp_nat_test_server_2.on('listening', function(){
    var address = udp_nat_test_server_2.address();
    var port = address.port;
    console.log(`NAT test 2 is listening at port ${port}`);
});

// print when server closes
udp_nat_test_server_2.on('close', function(){
    console.log("Socket closed");
});

udp_nat_test_server_2.bind(6512);

// check every second to see if a client has wrongly disconnected
setInterval(function timeout_loop(){
    console.log(sockets.length);
    if(sockets.length > 0){
        for(let socket=0; socket<sockets.length; socket++){
            console.log(sockets[socket][3]);
            if(sockets[socket][3] > 0 && sockets[socket][4] != -1){
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

function check_nat_type(socket, local_port, external_port_one, external_port_two){
    if(external_port_one != 0 && external_port_two != 0) {
        let nat_type = nat_types.Unknown;
        if(local_port == external_port_one && local_port == external_port_two){
            console.log("DirectMapping");
            nat_type = nat_types.DirectMapping;
        }
        else if(external_port_one == external_port_two){
            console.log("Restricted");
            nat_type = nat_types.Restricted;
        }
        else if(external_port_one != external_port_two){
            console.log("Symmetric");
            nat_type = nat_types.Symmetric;
        }
        socket.write(Buffer.from(JSON.stringify({
            "ID": msg_types.NATTypeResponse,
            "NATType": nat_type,
        })));
    }
}