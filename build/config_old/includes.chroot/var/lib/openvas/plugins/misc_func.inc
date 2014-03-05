# OpenVAS Vulnerability Test
# $Id: misc_func.inc 16226 2013-05-06 13:17:22Z veerendragg $
# Description: Miscellaneous support methods
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Veerendra G.G <veerendragg@secpod.com>
# Added new construct_rpc_packet() function to construct rpc packet
#
# Copyright:
# Copyright (C) 2002 Michel Arboi <arboi@alussinan.org>
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

# $Revision: 16226 $

function get_unknown_svc()
 {

   local_var port;
  
   if(!isnull(_FCT_ANON_ARGS[0])) {
     port = _FCT_ANON_ARGS[0];
   } else {
     port = get_kb_item("Services/unknown");
   } 

   if(!port)return 0;
   if (port == 139)return 0;

   if(service_is_unknown(port:port)) {
    return port;
   }  else {
    return 0;
   }  
 }     

function register_service(port, proto, ipproto)
{
  local_var	k;
  if (! ipproto) ipproto = "tcp";
  if (! service_is_unknown(port:port, ipproto: ipproto))
  {
    if (debug_level) display(get_host_ip(), ": service is already known on port ", ipproto, ":", port, "\n");
    #return(0);
  }
   
  if ( ipproto != "unknown" )
  {
   k = strcat("Known/", ipproto, "/", port);
   replace_kb_item(name: k, value: proto);
   if (ipproto == "tcp") k = strcat("Services/", proto);
   else k = strcat("Services/", ipproto, "/", proto);
   set_kb_item(name: k, value: port);
  }
   if (debug_level) display(get_host_ip(), ": register_service: port=", port, ", proto=", proto, "\n");
}

# This function may fork!
function known_service(port, ipproto)
{
  local_var	k, p;
  if (! ipproto) ipproto = "tcp";
  k = strcat("Known/", ipproto, "/", port);
  p = get_kb_item(k);
  #if (p) { display("Known service on port ", port, "\n"); }
  #else { display("Unknown service on port ", port, "\n"); }
  return p;
}

# This function does not fork!
function service_is_unknown(port, ipproto)
{
  local_var	k, p;
  if (! ipproto) ipproto = "tcp";
  k = strcat("Known/", ipproto, "/", port);
  p = get_kb_list(k);
  if (isnull(p)) return TRUE;
  foreach k (p)
    if (k != "unknown")	# fool proof
      return FALSE;
  return TRUE;
}

function verify_service(port, ipproto, proto)
{
  local_var	k, p;
  # Remember: no KB yet in command line mode!
  if (! ipproto) ipproto = "tcp";
  k = strcat("Known/", ipproto, "/", port);
  p = get_kb_list(k);
  foreach k (p)
    if (k == proto)
      return TRUE;
  return FALSE;
}

# This function may fork
function get_port_for_service(default, ipproto, proto)
{
  local_var	k, p;
  # Remember: no KB yet in command line mode!
  if (! ipproto) ipproto = "tcp";
  if (ipproto == "tcp") k = strcat("Services/", proto);
  else k = strcat("Services/", ipproto, "/", proto);
  p = get_kb_item(k);
  if (p) return p;
  k = strcat("Known/", ipproto, "/", default);
  p = get_kb_item(k);
  if (p == proto) return default;
  exit(0);
}

function set_mysql_version(port, version)
{
  local_var	sb;
  sb = string("mysql/version/", port);
  set_kb_item(name: sb, value: version);
}

function get_mysql_version(port)
{
  local_var sb;
  sb = string("mysql/version/", port);
  return  get_kb_item(sb);
}

function set_mariadb_version(port, version)
{
  local_var	sb;
  sb = string("mariadb/version/", port);
  set_kb_item(name: sb, value: version);
}

function get_mariadb_version(port)
{
  local_var sb;
  sb = string("mariadb/version/", port);
  return  get_kb_item(sb);
}

function get_unknown_banner(port, ipproto, dontfetch)
{
  local_var	sb, sbH, banner, soc, req, tcp, p, bannerHex;

  if (! ipproto) ipproto = "tcp";
  if ( ipproto == "tcp" )
	tcp = 1;
  else
	tcp = 0;

  if (tcp)
  {
   sb  = strcat("unknown/banner/", port);
   sbH = strcat("unknown/bannerHex/", port);
  }
  else
  {
   sb  = strcat("unknown/banner/", ipproto, "/", port);
   sbH = strcat("unknown/bannerHex/", ipproto, "/", port);
  }
  banner = get_kb_item(sbH);
  if (banner) return hex2raw(s: banner);
  banner = get_kb_item(banner);
  if (banner) return banner;

  banner = get_kb_item("BannerHex/"+port);
  if (banner) return(hex2raw(s: banner));
  banner = get_kb_item("Banner/"+port);
  if (banner) return(banner);
                                                                                
  banner = get_kb_item("Amap/"+ipproto+"/"+port+"/FullBanner");
  if (banner) return(banner);

  foreach p (make_list("spontaneous", "get_http", "help"))
  {
    banner = get_kb_item("FindService/"+ipproto+"/"+port+"/"+p);
    bannerHex = get_kb_item("FindService/"+ipproto+"/"+port+"/"+p+"Hex");
    if ( banner && bannerHex )  
    {
    if (strlen(bannerHex) > 2 * strlen(banner))
     return hex2raw(s: bannerHex);
    else
     return(banner);
    }
  }
  if (dontfetch) return(NULL);
  if (! get_port_state(port)) return (NULL);
  if (! tcp) return (NULL);

  soc = open_sock_tcp(port);
  if(!soc) return (NULL);
  # I don't think that it makes sense to send an HTTP request
  #req = http_head(item:"/", port:port);
  #send(socket:soc, data:req);
  banner = recv(socket:soc, length:2048);
  close(soc);
  if (banner)
  {
    replace_kb_item(name: sb, value: banner);
    if ('\0' >< sb)
     replace_kb_item(name: sbH, value: hexstr(banner));
  }
  return(banner);
}

function set_unknown_banner(port, banner, ipproto)
{
  local_var	sb;
  if (! ipproto || ipproto == 'tcp')
    sb = string("unknown/banner/", port);
  else
    sb = strcat('unknown/banner/', ipproto, '/', port);
  set_kb_item(name: sb, value: banner);
  if ('\0' >< banner)
  {
    if (! ipproto || ipproto == 'tcp')
      sb = string("unknown/bannerHex/", port);
    else
      sb = strcat('unknown/bannerHex/', ipproto, '/', port);
    set_kb_item(name: sb, value: hexstr(banner));
  }
}

#
# Get the banner for a given service
# You must also specify a default port, in case this is not in the kb
#
function get_service_banner_line(service, port, ipproto)
{
  local_var	banner, soc, key, gport, tcp;
  tcp = !ipproto || ipproto == 'tcp';
  if (tcp)
   gport = get_kb_item(strcat("Services/", service));
  else
   gport = get_kb_item(strcat("Services/", ipproto, "/", service));
  if(!gport) gport = port;

  if (tcp) 
   key = strcat(service, "/banner/", gport);
  else
   key = strcat(service, "/banner/", ipproto, "/", gport);

  banner = get_kb_item(key);
  
  if(!banner)
  {
    if (! tcp) return;

    if(get_port_state(gport))
    {
      soc = open_sock_tcp(gport);
      if(soc)
      { 
	banner = recv_line(socket:soc, length:2048);
	close(soc);
      }
    }
#   if (banner) set_kb_item(name: key, value: banner);
  }
  
  return(banner);
}
#
# Fast replacement for getrpcport() which uses the libc
#
function get_rpc_port(program, protocol, portmap)
{ 
 local_var	broken, req, soc, r, port;
 local_var	a, b, c, d, p_a, p_b, p_c, p_d, pt_a, pt_b, pt_c, pt_d;

 
 
 a = rand() % 255;
 b = rand() % 255;
 c = rand() % 255;
 d = rand() % 255;
 
 p_a = program / 16777216; 	p_a = p_a % 256;
 p_b = program / 65356; 	p_b = p_b % 256;
 p_c = program / 256;   	p_c = p_c % 256;
 p_d = program % 256;

 pt_a = protocol / 16777216; pt_a = pt_a % 256;
 pt_b = protocol / 65535   ; pt_b = pt_b % 256;
 pt_c = protocol / 256;    ; pt_c = pt_c % 256;
 pt_d = protocol % 256;
 
 
 req = raw_string(a, 	b, 	c, 	d, 	# XID
 		  0x00, 0x00, 0x00, 0x00,	# Msg type: call
		  0x00, 0x00, 0x00, 0x02,	# RPC Version
		  0x00, 0x01, 0x86, 0xA0,	# Program
		  0x00, 0x00, 0x00, 0x02,	# Program version
		  0x00, 0x00, 0x00, 0x03,	# Procedure
		  0x00, 0x00, 0x00, 0x00,	# Credentials - flavor
		  0x00, 0x00, 0x00, 0x00, 	# Credentials - length
		  0x00, 0x00, 0x00, 0x00,	# Verifier - Flavor
		  0x00, 0x00, 0x00, 0x00,	# Verifier - Length
		  
		  p_a,  p_b,  p_c,  p_d,	# Program
		  0xFF, 0xFF, 0xFF, 0xFF,	# Version (any)
		  pt_a, pt_b, pt_c, pt_d,	# Proto (udp)
		  0x00, 0x00, 0x00, 0x00	# Port
 		  );
	
	  
 if(isnull(portmap)){
   port = int(get_kb_item("rpc/portmap"));
   if(port == 0)port = 111;
   }
 else port = portmap;
 	  
	  
 broken = get_kb_item(string("/tmp/rpc/noportmap/", port));
 if(broken)return(0);
 
 	  
 soc = open_sock_udp(port);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1024);
 
 close(soc);
 if(!r)
 {
  set_kb_item(name:string("/tmp/rpc/noportmap/", port), value:TRUE);
  return(0);
 }
 
 if(strlen(r) < 28)
  return(0);
 else
  {
   p_d = ord(r[27]);
   p_c = ord(r[26]);
   p_b = ord(r[25]);
   p_a = ord(r[24]);
   port = p_a;
   port = port * 256;
   port = port +p_b; 
   port = port * 256;
   port = port + p_c; 
   port = port * 256;
   port = port + p_d;
   return(port);
  }
}

## This function will construct rpc packet
function construct_rpc_packet(program, prog_ver, procedure, data, udp, credentials, verifier)
{

  ## Add 0 If credentials are not passed
  if(isnull(credentials)){
    credentials[0] = 0;
    credentials[1] = 0;
  }

  ## Add 0 If Verified are not passed
  if(isnull(verifier)){
    verifier[0] = 0;
    verifier[1] = 0;
  }

  ## Random XID
  xid = rand();

  ## Construct complete RPC Rstat Request
  header  = mkdword(xid);                       ## XID
  header += mkdword(0);                         ## Message Type: Call (0)
  header += mkdword(2);                         ## RPC Version: 2
  header += mkdword(program);                   ## Prgram
  header += mkdword(prog_ver);                  ## Prgram Version
  header += mkdword(procedure);                 ## Procedure

  ## Credentials
  cred_data = mkdword(credentials[0]);          ## Flavor
  cred_data += mkdword(strlen(credentials[1])); ## Length

  ## Verifier
  verifier_data = mkdword(verifier[0]);          ## Flavor
  verifier_data += mkdword(strlen(verifier[1])); ## Length

  rpc_packet = header + cred_data + verifier_data + data;

  ## Add Fragment header if it's not UDP protocol
  if(udp != "udp" || udp == FALSE)
  {
    ## Fragment Length
    data_len = strlen(header + cred_data + verifier_data + data);

    ## Fragment Header
    frag_header  = mkbyte (0x80);               ## Last Fragment
    frag_header  += mkbyte (0);                 ##
    frag_header  += mkdword(data_len);          ## Fragment Length
    rpc_packet = frag_header + rpc_packet;
  }

  return(rpc_packet);
}

#
function rand_str(length, charset)
{
  local_var	l, i, s, n;

  if (! charset) 
   charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
  if (isnull(length))
    length = 8;
  l = strlen(charset);
  s = "";
  for (i = 0; i < length; i ++)
  {
    n = rand() % l;
    s += charset[n];
  }
  return s;
}



function add_port_in_list(list, port)
{
 local_var l;
 
 
 if(!get_port_state(port))
 {
  if(isnull(list))return make_list();
  else return list;
 }
 
 if(isnull(list))return make_list(port);
 
 foreach l (list)
 { 
  if(l == port)
   return list;
 }

 return make_list(list, port);
}

# hex2raw was written by Renaud?

function hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);	# remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2) {
	display("hex2raw: odd string: ", s, "\n");
	l --;
	}
 s = tolower(s);
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}

function report_service(port, svc, banner)
{
 local_var	k, name, a;

 svc = tolower(svc);
 if (! isnull(banner))
 {
  k = strcat(svc, "/banner/", port);
  set_kb_item(name: k, value: banner);
 }
 register_service(port: port, proto: svc);
 if (svc == 'www') name = 'web server';
 else if (svc == 'proxy') name = 'web proxy';
 else if (svc == 'hylafax-ftp' || svc == 'hylafax') name = 'HylaFAX server';
 else if (svc == 'agobot.fo') name = 'Agobot.fo backdoor';
 else if (svc == 'unknown_irc_bot') name = 'IRC bot';
 else if (svc == 'auth') name = 'identd';
 else name = toupper(svc) +' server';
 a = tolower(name[0]);
 if (a == 'a' || a == 'e' || a == 'i' || a == 'o') a = 'An ';
 else a = 'A ';
 security_note(port: port, data: a + name + ' is running on this port');
}



function base64_decode(str)
{
 local_var len, i, j, k, ret, base64, b64, a,b,c,o;
 len = strlen(str);
 ret = "";

 base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

 for (i = 0; i < 256; i++)
   b64[i] = 0;
 for (i = 0; i < strlen(base64); i++)
   b64[ord(base64[i])] = i;

 for(j=0;j<len;j+=4)
 {
   for (i = 0; i < 4; i++)
   {
    c = ord(str[j+i]);
    a[i] = c;
    b[i] = b64[c];
   }
 
   o[0] = (b[0] << 2) | (b[1] >> 4);
   o[1] = (b[1] << 4) | (b[2] >> 2);
   o[2] = (b[2] << 6) | b[3];
   if (a[2] == ord('='))
     i = 1;
   else if (a[3] == ord('='))
     i = 2;
   else
     i = 3;
   for(k=0;k<i;k++)
      ret += raw_string(int(o[k]) & 255);
   
   if (i < 3) 
     break;
 }

 return ret;
}

__base64_code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function base64_code(c)
{
 return(__base64_code[c]);
}

function pow2(x)
{
 local_var __ret;

 __ret = 1;
 while(x)
  {
  __ret = __ret * 2;
  x = x  - 1;
  }
 return(__ret);
}

function base64(str)
{
 local_var len, i, ret, char_count, _bits, val, cnt, mul;

 len = strlen(str);
 i = 0;
 ret = "";
 char_count = 0;
 _bits = 0;
 while(i < len)
 {
  _bits = _bits + ord(str[i]);
  char_count = char_count + 1;
  if(char_count == 3)
  {
    val = _bits / 262144;
    ret = string(ret, base64_code(c:val));
    val = _bits / 4096;
    val = val & 0x3F;
    ret = string(ret, base64_code(c:val));
    val = _bits / 64;
    val = val & 0x3F;
    ret = string(ret, base64_code(c:val));
    val = _bits & 0x3F;
    ret = string(ret, base64_code(c:val));
    char_count = 0;
    _bits = 0;
 }
 else {
       _bits = _bits * 256;
       }
 i = i + 1;
 }


 if(!(char_count == 0))
 {
  cnt = char_count * 8;
  mul = 16;
  mul = mul - cnt;
  mul = pow2(x:mul);
  _bits = _bits * mul;
  val = _bits / 262144;
  ret = string(ret, base64_code(c:val));
  val = _bits / 4096;
  val = val & 0x3F;
  ret = string(ret, base64_code(c:val));
 if(char_count == 1)
 { 
  ret = string(ret, "==");
 }
 else
 {
   val = _bits / 64;
   val = val & 0x3F;
   ret = string(ret, base64_code(c:val), "=");
  }
 }
 return(ret);
}


# This function converts a string representing a decimal number to 
# to hexadecimal; eg, dec2hex(1098757090) == "417db3e2".
#
# Args:
#   o num, decimal number.
#
# Return:
#   hex number represented as a raw string.
#
# updated: 16-Nov-2004, George A. Theall
#
function dec2hex(num) {
  local_var digits, hex, rem;
  hex = "";

  num = int(num);
  while (num > 0) {
    rem = num % 256;
    hex = raw_string(rem, hex);
    num = num / 256;
    if (num > 0 && num < 255) {
      hex = raw_string(num, hex);
      num = 0;
    }
  }
  if (!hex) hex = raw_string(0x00);

  return hex;
}

# Convert a Date CVS field to Unix time 
# Michel Arboi

function cvsdate2unixtime(date)
{
  local_var v, u;
  v = eregmatch(string: date, pattern: ".Date: ([0-9]+)/([01][0-9])/([0-3][0-9]) ([0-2][0-9]):([0-6][0-9]):([0-6][0-9]) \$");
  if (isnull(v)) return;
  u = mktime(year: v[1], mon: v[2], mday: v[3], hour: v[3], min: v[5], sec: v[6]);
  return u;
}

