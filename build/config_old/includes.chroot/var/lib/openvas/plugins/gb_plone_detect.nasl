###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plone_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Plone  Detection
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
tag_summary = "Detection of Plone CMS.
                    
The script sends a connection request to the server and attempts to
determine if it is a Plone CMS from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103735";   

if (description)
{
 
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"detection", value:"remote probe");
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-06-12 11:17:19 +0200 (Wed, 12 Jun 2013)");
 script_name("Plone Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Plone CMS");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/plone","/Plone","/cms",cgi_dirs());

foreach dir (dirs) {

  url = string(dir, "/index.php");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( buf == NULL )continue;

    if(egrep(pattern:'<meta name="generator" content="Plone', string: buf, icase: TRUE))
    {
      if(strlen(dir)>0) {
        install=dir;
      } else {
        install=string("/");
      }

      set_kb_item(name:"plone/installed",value:TRUE);
      cpe = 'cpe:/a:plone:plone';

      register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);
      log_message(data:'Plone CMS was detected at ' + install + '.\nCPE: ' + cpe + '\n', port:port);

      exit(0);
  

 }
} 
exit(0);
