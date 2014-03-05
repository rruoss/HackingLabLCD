###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_drac_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Dell Remote Access Controller Detection
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
tag_summary = "Detection of Dell Remote Access Controller.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103680";   

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-03-18 17:03:03 +0100 (Mon, 18 Mar 2013)");
 script_name("Dell Remote Access Controller Detection");
 script_tag(name:"detection", value:"remote probe");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Dell Remote Access Controller");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = 443;
if(!get_port_state(port))exit(0);

urls = make_array();
info_url = make_array();
info_url_regex = make_array();

urls['/cgi/lang/en/login.xsl'] = 'Dell Remote Access Controller ([0-9]{1})';
urls['/public/about.html'] = 'Integrated Dell Remote Access Controller ([0-9]{1})';
urls['/cgi/about'] = 'Dell Remote Access Controller ([0-9]{1})';
urls['/Applications/dellUI/Strings/EN_about_hlp.htm'] = 'Integrated Dell Remote Access Controller ([0-9]{1})';

info_url[4] = make_list('/cgi/about');
info_url_regex[4] = make_list('var s_build = "([^"]+)"');

info_url[5] = make_list('/cgi-bin/webcgi/about');
info_url_regex[5] = make_list('<FirmwareVersion>([^<]+)</FirmwareVersion>');

info_url[6] = make_list('/public/about.html','/Applications/dellUI/Strings/EN_about_hlp.htm');
info_url_regex[6] = make_list('Version ([^<]+)<br>','Version ([0-9.]+)');

info_url[7] = make_list('/public/about.html');
info_url_regex[7] = make_list('var fwVer = "([^"]+)";');

foreach url (keys(urls)) {

  buf = FALSE;
  iv = FALSE;
  iv_url = FALSE;

  soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
  if(!soc)exit(0);

  req = http_get(item:url, port:port);
  send(socket:soc, data:req);
  while(recv = recv(socket:soc, length:2048)) {
    buf += recv;
  }  

  if("Content-Encoding: gzip" >< buf) buf = http_gunzip(buf:buf);

  if(!buf)continue;

  if(egrep(pattern:urls[url], string:buf)) {

    version = eregmatch(pattern:urls[url], string:buf);
    if(isnull(version[1]))continue;

    set_kb_item(name:"dell_remote_access_controller/version", value:version[1]);
    cpe = build_cpe(value:version[1], exp:"^([0-9]{1})", base:"cpe:/h:dell:remote_access_card:");
    if(!cpe)
      cpe = 'cpe:/h:dell:remote_access_card';

    iv = int(version[1]);
    iv_urls = info_url[iv];

    if(iv_urls) {

      foreach iv_url (iv_urls) {

        info_buf = FALSE;

        soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);

        if(soc) {

          req = http_get(item:iv_url, port:port);

          send(socket:soc, data:req);
          while(recv = recv(socket:soc, length:2048)) { 
            info_buf += recv;
          }  

          close(soc);

          if(!info_buf) continue;

          if("Content-Encoding: gzip" >< info_buf) info_buf = http_gunzip(buf:info_buf);

          foreach iur (info_url_regex[iv]) {
            fw_version = eregmatch(pattern:iur, string:info_buf);
            if(!isnull(fw_version[1])) { 
              fw = fw_version[1];
              break;
            }  
          }  

          if(fw) {

            set_kb_item(name:"dell_remote_access_controller/fw_version", value:fw);

            cpe_fw = str_replace(string:tolower(fw), find:" ", replace:"_");
            cpe_fw = str_replace(string:tolower(cpe_fw), find:"(", replace:"_");
            cpe_fw = str_replace(string:tolower(cpe_fw), find:")", replace:"");
            cpe_fw = str_replace(string:tolower(cpe_fw), find:"__", replace:"_");

            cpe = cpe + ':firmware_' + cpe_fw;
          }  

        }  
      
      }  

    }   

    if(soc)close(soc);

    if(!fw) fw = version[1];

    register_product(cpe:cpe, location:url, nvt:SCRIPT_OID, port:port);
    log_message(data: build_detection_report(app:"Dell Remote Access Controller", version:fw, install:url, cpe:cpe, concluded: version[0]),
                port:port);

    exit(0);

  }  

}  

exit(0);
