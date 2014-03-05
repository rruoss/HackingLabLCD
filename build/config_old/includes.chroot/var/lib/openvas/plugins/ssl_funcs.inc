# OpenVAS Vulnerability Test
# Description: Implementation of common ssl functions
# Authors:
# Laban Mwangi <lmwangi@penguinlabs.co.ke>
#
# Copyright:
# Copyright (c) 2008 PenguinLabs. http://www.penguinlabs.co.ke
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

SSL_v2 = raw_string(0x02,0x00);
SSL_v3 = raw_string(0x03,0x00);
TLS_10 = raw_string(0x03,0x01);
TLS_11 = raw_string(0x03,0x02);
TLS_12 = raw_string(0x03,0x03);

version_string = make_list();

version_string[SSL_v2] = 'SSLv2';
version_string[SSL_v3] = 'SSLv3';
version_string[TLS_10] = 'TLSv1.0';
version_string[TLS_11] = 'TLSv1.1';
version_string[TLS_12] = 'TLSv1.2';

function get_server_cert(port, format)
{
    local_var mesgoffset, off, mesgsize;

    if(get_port_state(port))
    {
	soc = open_sock_tcp(port, transport:ENCAPS_IP);

	if(soc)
	{
	    #send a client hello and get response
	    serverhello = send_ssl_client_hello(socket:soc);

	    #used to iterate over tls records
	    byteoffset = 0;

	    #certificate length - Used by substring to chunk out a cert
	    certsize = 0;

	    #check whether it's a handshake
            #display("len(serverhello)=", strlen(serverhello), "\n");
	    while (byteoffset < strlen(serverhello))
	    {
                recordsize = ord(serverhello[byteoffset+3])*256
                           + ord(serverhello[byteoffset+4]);
                #display("  reading record off=", byteoffset,
                #        " type=", hex(ord(serverhello[0+byteoffset])),
                #        " size=", recordsize, "\n");
	    	if (ord(serverhello[0+byteoffset]) == 0x16)
	    	{
                    #used to iterate over handshake messages.
                    mesgoffset = 0;

                    while (mesgoffset < recordsize)
                    {
                        off = byteoffset + mesgoffset + 5;
	    		mesgsize = ord(serverhello[off+1])*65536
                                 + ord(serverhello[off+2])*256
                                 + ord(serverhello[off+3]);
                        #display("    handshake mesg off=", mesgoffset,
                        #        " type=",
                        #        hex(ord(serverhello[off])),
                        #        " size=", mesgsize, "\n");

	    		#check for the handshake type:  certificate
	    		if (ord(serverhello[off]) == 0x0b)
	    		{
	    		    #Get the certificate size
	    		    certsize = ord(serverhello[off+7])*4096
                                     + ord(serverhello[off+8])*256
                                     + ord(serverhello[off+9]);
	    		    #Substring certificate
	    		    cert = substr(serverhello, off+10,
                                          off+10+certsize-1);

	    		    close(soc);

	    		    return cert;
	    		}
                        mesgoffset = mesgoffset + 4 + mesgsize;
                    }
	    	}
	    	#If we get here, this isn't the correct record type,
	    	#Lets offset,rinse and repeat
	    	byteoffset = byteoffset + 5 + recordsize;
	    }

	    #We didn't get a cert
	    close(soc);
	    return 0;
        }
    }
}

function send_ssl_client_hello(socket, version, len)
{

        if(!version) version = TLS_10;
        if(!len) len = 10000;

	# Send an sslv2 client Hello
	req = raw_string (
			0x80, 0x74, 0x01) + 
                        version + 
                        raw_string(0x00, 0x4b, 0x00,
			0x00, 0x00, 0x20, 0x00, 0x00, 0x39, 0x00, 0x00,
			0x38, 0x00, 0x00, 0x35, 0x00, 0x00, 0x16, 0x00,
			0x00, 0x13, 0x00, 0x00, 0x0a, 0x07, 0x00, 0xc0,
			0x00, 0x00, 0x33, 0x00, 0x00, 0x32, 0x00, 0x00,
			0x2f, 0x03, 0x00, 0x80, 0x00, 0x00, 0x05, 0x00,
			0x00, 0x04, 0x01, 0x00, 0x80, 0x00, 0x00, 0x15,
			0x00, 0x00, 0x12, 0x00, 0x00, 0x09, 0x06, 0x00,
			0x40, 0x00, 0x00, 0x14, 0x00, 0x00, 0x11, 0x00,
			0x00, 0x08, 0x00, 0x00, 0x06, 0x04, 0x00, 0x80,
			0x00, 0x00, 0x03, 0x02, 0x00, 0x80, 0x3a, 0xaa,
			0xc8, 0xd9, 0x60, 0xbe, 0x63, 0x7c, 0x85, 0xb3,
			0x17, 0xa6, 0xb7, 0xa8, 0xec, 0x2e, 0x45, 0x2c,
			0x8a, 0x63, 0xf0, 0x6f, 0x9d, 0x59, 0x70, 0x92,
			0x0a, 0xd1, 0xc6, 0xbf, 0xdd, 0xbf );
	send(socket:socket, data:req);

	#Get as much data as we can. We expect a server hello, certificate, kex, done ...
	response = recv(socket:socket, length:len);

	return response;

}
