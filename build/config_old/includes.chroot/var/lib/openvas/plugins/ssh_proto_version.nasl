###############################################################################
# OpenVAS Vulnerability Test
# $Id: ssh_proto_version.nasl 43 2013-11-04 19:51:40Z jan $
#
# SSH Protocol Versions Supported
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Identification of SSH protocol versions supported by the remote
SSH Server. Also reads the corresponding fingerprints from the service.

The following versions are tried: 1.33, 1.5, 1.99 and 2.0";

if (description)
{
 script_id(100259);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-08-25 21:06:41 +0200 (Tue, 25 Aug 2009)");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("SSH Protocol Versions Supported");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the supported SSH Protocol Versions");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("global_settings.inc");
include("ssh_func.inc");

port = get_kb_item("Services/ssh");
if(!port)port = 22;

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
close(soc);

function read_key(key) {

 local_var key, len, fingerprint, x;

  key_hex = hexstr(MD5(key));
  len = strlen(key_hex); # 32

  for(x = 0; x < len; x += 2) {
    fingerprint += substr(key_hex,x,x+1);
    if(x+2<len) {
       fingerprint += ":";
     }
  }  
 if("ssh-rsa" >< key) {
   set_kb_item(name:string("SSH/",port,"/fingerprint/ssh-rsa"), value:fingerprint);
 } 
 if("ssh-dss" >< key) {
   set_kb_item(name:string("SSH/",port,"/fingerprint/ssh-dss"), value:fingerprint);
 }  

 return fingerprint;

}

function get_fingerprint(version) {

 local_var buf, header, fingerprint, key, len, version, soc;

 soc = open_sock_tcp(port);
 if(!soc)return FALSE;

 if(version == "2.0") {

   ssh_login(socket:soc);
   key = get_server_host_key();

   close(soc);
   if(!key)return FALSE;

   if(fingerprint = read_key(key:key)) {
     return fingerprint;
   } else {
     return FALSE;
   }
  } 

 else if(version == "1.5") {

   buf = recv_line(socket:soc, length:8192);
   send(socket:soc, data:'SSH-1.5-OpenVAS_1.0\n');

   header = recv(socket:soc, length:4);
   if(strlen(header)<4)return FALSE;

   len = ord(header[2])*256+ord(header[3]);
   buf = recv(socket:soc, length:len);
   if(!buf)return FALSE;
   buf = header + buf;

   close(soc);

   if(!key = substr(buf,132,259)+raw_string(0x23))return FALSE;
   if(fingerprint = read_key(key:key)) {
      return fingerprint;
   } else {
      return FALSE;
   }
 }
 else {
   close(soc);
   return FALSE;
 }
  return fingerprint;
}

versions = make_list("1.33","1.5","1.99","2.0");

foreach version (versions) {

  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  ret = recv_line(socket:soc, length:512);
  if(!ret) {
    close(soc);
    exit(0);
  }

  if(!egrep(pattern:"^SSH-.*", string:ret)){
    close(soc);
    return(0);
  }

  request = string("SSH-", version, "-OpenVASSSH_1.0\n");
  send(socket:soc, data:request);

  ret = recv_line(socket:soc, length:500);
  close(soc);

  if(!egrep(pattern:"Protocol.*differ", string: ret)) {
   supported_versions[version]=version; 
  }   
}

if((report_verbosity > 0) && (supported_versions)) {
  
  foreach supported (supported_versions) {
   if(supported == "2.0" || supported == "1.5") {
     if(fingerprint = get_fingerprint(version:supported)) {
       if(supported == "2.0") {
         fingerprint_info += string("SSHv2 Fingerprint: ", fingerprint, "\n");
	 set_kb_item(name: string("SSH/",port,"/fingerprint/v2"), value: fingerprint);
       } 
       else if(supported == "1.5") {
         fingerprint_info += string("SSHv1 Fingerprint: ", fingerprint, "\n");
	 set_kb_item(name: string("SSH/",port,"/fingerprint/v1"), value: fingerprint);
       }
     }
   }
   info += string(chomp(supported),"\n");
  }

  if(fingerprint_info) {
    info += string("\n", fingerprint_info);
  }

  set_kb_item(name:"SSH/supportedversions/" + port,value: supported_versions);
 
  log_message(port:port,data: 'The remote SSH Server supports the following SSH Protocol Versions:\n'+info);
  exit(0);
}

exit(0);
