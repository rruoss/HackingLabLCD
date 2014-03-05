###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssl_common_name_fqdn.nasl 13 2013-10-27 12:16:33Z jan $
#
# SSL Certificate - Subject Common Name Does Not Match Server FQDN
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "The SSL certificate contains a common name (CN) that does not match
the hostname.";

desc = "
 Summary:
 " + tag_summary;
if (description)
{
 
 script_id(103141);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-04-27 15:13:59 +0200 (Wed, 27 Apr 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("SSL Certificate - Subject Common Name Does Not Match Server FQDN");
 
 script_description(desc);
 script_summary("Checks if Subject Common Name match the Server FQDN");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("nmap_nse/gb_nmap_ssl_cert.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include ("http_func.inc");

# Get HTTP Ports
port = get_http_port(default:443);
if(!port){
    exit(0);
}

if(!subject = get_kb_item(string("ssl/nmap/",port,"/subject")))exit(0);
cn = eregmatch(pattern:"commonName=([^/]+)/", string:subject);
if(isnull(cn[1]))exit(0);

hostname = get_host_name();
ip = get_host_ip();

if(hostname == ip)exit(0);

if(cn[1] != hostname) {
  desc = string(desc,"\n\nHostname: ",hostname,"\nCommon Name: ",cn[1],"\n");
  security_warning(port:port,data:desc);
  exit(0);
} else {
  log_message(port:port,data:string(desc,"\n\nHostname: ",hostname," match the Common Name: ",cn[1],"\n"));
  exit(0);
}  

exit(0);
