###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ssl_ciphers.nasl 77 2013-11-25 13:45:17Z mime $
#
# Check SSL Weak Ciphers and Supported Ciphers
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This plugin connects to a SSL server and checks for
  weak ciphers.

  Note: Depending on the 'List SSL Supported Ciphers' preference, the plugin might take
  good amount of time to complete, it is advised to increase the plugin timeout, if
  no results appear.";


if(description)
{
  script_id(900234);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 77 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-25 14:45:17 +0100 (Mon, 25 Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-04-13 17:43:57 +0200 (Tue, 13 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Check SSL Weak Ciphers and Supported Ciphers");
  desc = "

  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check SSL Weak Ciphers");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_dependencies("secpod_ssl_ciphers_setting.nasl",
                      "secpod_open_tcp_ports.nasl");
  script_family("General");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("secpod_ssl_ciphers.inc");

## Get all tcp ports
sslPort = get_kb_item("TCP/PORTS");
enable_ssl_suported_cipher = get_kb_item("SSL/SupportedCiphers/Enabled");

## It will list all the supported ciphers,
## If check_sup_ciphers is TRUE
check_sup_ciphers = FALSE;

## List all supported ciphers, If kb above value sets as yes.
## Default it won't list supported ciphers
if(enable_ssl_suported_cipher == 'yes'){
  check_sup_ciphers = TRUE;
}

  complete_note = "";
  supported_ciphers = "";
  weak_ciphers = "";
  medium_ciphers = "";

if(sslPort)
{
  ## Check for ssl port by sending client hello
  ## and by analysing server hello response
  sock = open_sock_tcp(sslPort, transport: ENCAPS_SSLv23);
  if(!sock){
    sock = open_sock_tcp(sslPort, transport: ENCAPS_TLSv1);
    if(!sock){
        SSL_VER = "sslv2";
        CIPHER_CODE = raw_string(0x01, 0x00, 0x80);
        c_hello = construct_ssl_req(SSL_VER:SSL_VER, CIPHER:CIPHER_CODE);
        s_hello = get_ssl_server_hello(ssl_req:c_hello, sslPort:sslPort);
        if(!s_hello || isnull(s_hello)){
          exit(0); # no ssl port
        }
        if(!(ord(s_hello[2]) == 4 && ord(s_hello[5]) == 0 && ord(s_hello[6]) == 2)){
          exit(0); # no ssl port
        }
    }
  }

  ## Close Socket
  if(sock){
    close(sock);
  }


  ## SSLv2 Cipher test
  SSL_VER="sslv2";
  sslv2_sup = FALSE;

  ## Iterate over cipher specs and report weak and
  ## supported ciphers(if check_sup_ciphers is TRUE)
  for(i=0; i < max_index(sslv2_ciphers_codes); i++)
  {
    ## Get cipher code and cipher name
    CIPHER_CODE = sslv2_ciphers_codes[i];
    CIPHER_NAME = sslv2_ciphers_disply[i];

    ## Continue if it's not a weak cipher and
    ## check_sup_ciphers is FALSE
    if(!(check_sup_ciphers || "Weak Cipher" >< CIPHER_NAME ||
         "Medium Cipher" >< CIPHER_NAME)){
      continue;
    }

    ## Construct SSLv2 Request with given cipher spec
    req = construct_ssl_req(SSL_VER:SSL_VER, CIPHER:CIPHER_CODE);
    res = get_ssl_server_hello(ssl_req:req, sslPort:sslPort);

    if(!res || isnull(res)){
      continue;
    }

    ## To handle "Connection rate limit exceeded" or some other error message
    if(!(ord(res[2]) == 4 && ord(res[5]) == 0 && ord(res[6]) == 2)){
      continue;
    }

    ## Confirm SSLv2 is supported
    if(!sslv2_sup){
      sslv2_sup = TRUE;
    }

    ## SSLv2 Cipher spec supported?
    if(check_sslv2_cipher_spec_supported(server_hello:res))
    {
      supported_ciphers += '\n  ' + ereg_replace(pattern:": (High|Medium|Weak) Cipher",
                           replace:"", string:CIPHER_NAME);

      ## Check for weak cipher
      if("Weak Cipher" >< CIPHER_NAME){
        weak_ciphers += '\n  ' + CIPHER_NAME - " : Weak Cipher";
      }

      ## Check for Medium ciphers
      if("Medium Cipher" >< CIPHER_NAME){
        medium_ciphers += '\n  ' + CIPHER_NAME - " : Medium Cipher";
      }
    }
  }

  ## Report Server Supports SSLv2 or not
  if(sslv2_sup){
    complete_note += 'Server supports SSLv2 ciphers.';
  }else{
    complete_note += 'Server will not support SSLv2 Ciphers.';
  }


  ## SSLv3 Cipher test
  SSL_VER="sslv3";
  sslv3_sup = FALSE;

  ## Iterate over cipher specs and report weak and
  ## supported ciphers(if check_sup_ciphers is TRUE)
  for(i=0; i < max_index(sslv3_tlsv1_ciphers_codes); i++)
  {
    ## Get cipher code and cipher name
    CIPHER_CODE = sslv3_tlsv1_ciphers_codes[i];
    CIPHER_NAME = sslv3_ciphers_disply[i];

    ## Continue if it's not a weak cipher and
    ## check_sup_ciphers is FALSE
    if(!(check_sup_ciphers || "Weak Cipher" >< CIPHER_NAME ||
        "Medium Cipher" >< CIPHER_NAME)){
      continue;
    }

    ## Construct SSLv3 Request with given cipher spec
    req = construct_ssl_req(SSL_VER:SSL_VER, CIPHER:CIPHER_CODE);
    res = get_ssl_server_hello(ssl_req:req, sslPort:sslPort);

    if(!res || isnull(res)){
      continue;
    }

    ## To handle "Connection rate limit exceeded" or some other error message
    ## res[0] == 21 (Alert : hand shake fail)
    ## res[0] == 22 (Handshake : hand shake success)
    if(!((ord(res[0]) == 21 || ord(res[0]) == 22) 
       && ord(res[1]) == 3 && ord(res[2]) == 0)){
       continue;
    }

    ## Confirm SSLv3 is supported
    if(!sslv3_sup){
      sslv3_sup = TRUE;
    }

    ## Cipher spec supported?
    if(check_sslv3_cipher_spec_supported(server_hello:res))
    {
      supported_ciphers += '\n  ' + ereg_replace(pattern:" : (High|Medium|Weak) Cipher",
                           replace:"", string:CIPHER_NAME);

      ## Check for weak cipher
      if("Weak Cipher" >< CIPHER_NAME){
        weak_ciphers += '\n  ' + CIPHER_NAME - " : Weak Cipher";
      }

      ## Check for Medium ciphers
      if("Medium Cipher" >< CIPHER_NAME){
        medium_ciphers += '\n  ' + CIPHER_NAME - " : Medium Cipher";
      }
    }
  }

  ## Report Server Supports SSLv3 or not
  if(sslv3_sup){
    complete_note += '\n\nServer supports SSLv3 ciphers.';
  }else{
    complete_note += '\n\nServer will not support SSLv3 Ciphers.';
  }


  ## TLSv1 Cipher test
  SSL_VER="tlsv1";
  tlsv1_sup = FALSE;

  ## Iterate over cipher specs and report weak and
  ## supported ciphers(if check_sup_ciphers is TRUE)
  for(i=0; i < max_index(sslv3_tlsv1_ciphers_codes); i++)
  {
    ## Get cipher code and cipher name
    CIPHER_CODE = sslv3_tlsv1_ciphers_codes[i];
    CIPHER_NAME = tlsv1_ciphers_disply[i];

    ## Continue if it's not a weak cipher and
    ## check_sup_ciphers is FALSE
    if(!(check_sup_ciphers || "Weak Cipher" >< CIPHER_NAME ||
         "Medium Cipher" >< CIPHER_NAME)){
      continue;
    }

    ## Construct SSLv3 Request with given cipher spec
    req = construct_ssl_req(SSL_VER:SSL_VER, CIPHER:CIPHER_CODE);
    res = get_ssl_server_hello(ssl_req:req, sslPort:sslPort);

    if(!res || isnull(res)){
      continue;
    }

    ## To handle "Connection rate limit exceeded" or some other error message
    ## res[0] == 21 (Alert : hand shake fail)
    ## res[0] == 22 (Handshake : hand shake success)
    if(!((ord(res[0]) == 21 || ord(res[0]) == 22) 
       && ord(res[1]) == 3 && ord(res[2]) == 0)){
       continue;
    }

    ## Confirm TLSv1 is supported
    if(!tlsv1_sup){
      tlsv1_sup = TRUE;
    }

    ## Cipher spec supported?
    if(check_tlsv1_cipher_spec_supported(server_hello:res))
    {
      supported_ciphers += '\n  ' + ereg_replace(pattern:": (High|Medium|Weak) Cipher",
                           replace:"", string:CIPHER_NAME);

      ## Check for weak cipher
      if("Weak Cipher" >< CIPHER_NAME){
        weak_ciphers += '\n  ' + CIPHER_NAME - " : Weak Cipher";
      }

      ## Check for Medium ciphers
      if("Medium Cipher" >< CIPHER_NAME){
        medium_ciphers += '\n  ' + CIPHER_NAME - " : Medium Cipher";
      }
    }
  }
  ## Report Server Supports TLSv1 or not
  if(tlsv1_sup){
    complete_note += '\n\nServer supports TLSv1 ciphers.';
  }else{
    complete_note += '\n\nServer will not support TLSv1 Ciphers.';
  }


  ## Final Reporting Section for Medium Ciphers, Weak Ciphers and
  ## Supported Ciphers
  if(check_sup_ciphers){
    if(supported_ciphers) {
      complete_note += '\n\nServer supported ciphers are ' + supported_ciphers;
      set_kb_item(name:string("secpod_ssl_ciphers/",sslPort,"/supported_ciphers"), value: supported_ciphers);
    }  
  }

  if(medium_ciphers){
    set_kb_item(name:"secpod_ssl_ciphers/medium", value:TRUE);
    set_kb_item(name:string("secpod_ssl_ciphers/",sslPort,"/medium"), value:TRUE);
    medium_ciphers = complete_note + '\n\nMedium Ciphers ' + medium_ciphers;
    set_kb_item(name:string("secpod_ssl_ciphers/",sslPort,"/medium_ciphers"),
                value:medium_ciphers);
  }

  if(weak_ciphers){
    set_kb_item(name:"secpod_ssl_ciphers/weak", value:TRUE);
    set_kb_item(name:string("secpod_ssl_ciphers/",sslPort,"/weak"), value:TRUE);
    complete_note += '\n\nWeak Ciphers ' + weak_ciphers;
  }else{
    complete_note += '\n\nNone of the weak ciphers are supported';
  }

  ## Store Final report in KB
  set_kb_item(name:string("secpod_ssl_ciphers/",sslPort,"/report"), value:complete_note);
}
