###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tls_version.nasl 77 2013-11-25 13:45:17Z mime $
#
# TLS Version Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103823";   

if (description)
{
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 77 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-25 14:45:17 +0100 (Mon, 25 Nov 2013) $");
 script_tag(name:"creation_date", value:"2013-10-29 12:36:43 +0100 (Tue, 29 Oct 2013)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"detection", value:"remote probe");
 script_name("TLS Version Detection");

tag_summary =
"The script sends a connection request to the server and attempts to
extract the TLS version number from the reply.";

desc = "Summary:
" + tag_summary;

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }

 script_description(desc);
 script_summary("Try to determine the TLS Version");
 script_category(ACT_END);
 script_family("General");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("secpod_open_tcp_ports.nasl","secpod_ssl_ciphers.nasl");
 script_mandatory_keys("TCP/PORTS");
 script_add_preference(name:"Report TLS version", type:"checkbox", value: "no");
 exit(0);
}

include("ssl_funcs.inc");
include("host_details.inc");

function get_tls_app(port) {

  local_var cpe_str;

  host_details = get_kb_list("HostDetails/NVT/*");

  if(!host_details) return;
  
  foreach host_detail (keys(host_details)) {

    if("cpe:/" >< host_detail) {

      host_values = split(host_detail, sep:"/", keep:FALSE);

      if(isnull(host_values[2])) continue;
      oid = host_values[2];

      ports = get_kb_list("HostDetails/NVT/" + oid + "/port"); # dont use get_kb_item(), because this could fork. 
      if(!ports) continue;

      foreach p (ports) {
        if(p == port) {
          if(host_values[4] >!< cpe_str) {
            cpe_str += 'cpe:/' +  host_values[4] + ';';
          }  
        } 
      }

    }

  }

  if(strlen(cpe_str)) {
    cpe_str = ereg_replace(string:cpe_str, pattern:"(;)$", replace:"");
    return cpe_str;
  }  

}

function get_port_ciphers(port) {

  local_var ciphers, cipher, ciphers_split, cs, ret_ciphers;

  ret_ciphers = '';

  if(!port)return;

  ciphers = get_kb_item('secpod_ssl_ciphers/' + port + '/supported_ciphers');
  if(!ciphers)return;

  ciphers_split = split(ciphers, keep:FALSE);
  foreach cs (ciphers_split) {

    cipher = ereg_replace(string:cs, pattern: " : SSL_NOT_EXP", replace:"");
    cipher = str_replace(string: cipher, find:" ", replace:"");
    cipher = str_replace(string: cipher, find:'\n', replace:"");
    chomp(cipher);

    if(!isnull(cipher) && cipher != "")
      ret_ciphers += cipher + ';';

  }  

  ret_ciphers = ereg_replace(string:ret_ciphers, pattern:"(;)$", replace:"");

  return ret_ciphers;

}  

enable_log  = script_get_preference("Report TLS version");

ports = get_kb_list("TCP/PORTS");
if(!ports) exit(0);

foreach port (ports) {

  sup_tls = '';
  cpe = '';

  foreach vers (make_list(TLS_10,TLS_11,TLS_12,SSL_v2,SSL_v3)) {

    soc = open_sock_tcp(port, transport:ENCAPS_IP);
    if(!soc) continue;

    for(i=0; i<3; i++) {
      ret = send_ssl_client_hello(socket:soc, version:vers, len:4);
      if(ret)break;
    }  

    close(soc);


    if(!ret || strlen(ret) < 4)continue;

    version = substr(ret,1,2);

    if(version == vers) {
      sup_tls += version_string[version] + ';';
      register_host_detail(name:"TLS/port", value:port, nvt:SCRIPT_OID, desc:"TLS Version Detection");
      register_host_detail(name:"TLS/" + port, value:version_string[version], nvt:SCRIPT_OID, desc:"TLS Version Detection"); 
    }  

  }  

  if(strlen(sup_tls)) {
    sup_tls = ereg_replace(string:sup_tls, pattern:"(;)$", replace:"");
    supported_tls[port] = sup_tls;
  }

}

if('yes' >!< enable_log) exit(0);

if(supported_tls) {

  host = get_host_name();
  ip = get_host_ip();
  text = 'IP,Host,Port,TLS-Version,Ciphers,Application-CPE\n';

  foreach p (keys(supported_tls)) {

    text += ip + ',' + host + ',' +  p + ',' + supported_tls[p];

    ciphers = get_port_ciphers(port:p);

    if(ciphers)
      text += ',' + ciphers;

    cpe = get_tls_app(port:p);

    if(cpe)
      text += ',' + cpe + '\n';
    else
      text += '\n';

    text = ereg_replace(string:text, pattern:'\n\n', replace:'\n');

    report = TRUE;
  }  

  if(report) {
    log_message(port:0, data:text);
    exit(0);
  }  

}  

exit(0);
