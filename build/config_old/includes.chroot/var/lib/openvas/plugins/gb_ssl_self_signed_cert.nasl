###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssl_self_signed_cert.nasl 13 2013-10-27 12:16:33Z jan $
#
# SSL Certificate - Self-Signed Certificate Detection
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
tag_summary = "The ssl certificate on this Port is self signed.";

if (description)
{
 
 script_id(103140);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-04-27 15:13:59 +0200 (Wed, 27 Apr 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

desc = "
 Summary:
 " + tag_summary;


 script_name("SSL Certificate - Self-Signed Certificate Detection");
 script_description(desc);
 script_summary("Checks for Self-Signed Certificates");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("nmap_nse/gb_nmap_ssl_cert.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://en.wikipedia.org/wiki/Self-signed_certificate");
 exit(0);
}

include ("http_func.inc");

## Get HTTP Ports
port = get_http_port(default:443);
if(!port){
    exit(0);
}

if(!issuer  = get_kb_item(string("ssl/nmap/",port,"/issuer")))exit(0);
if(!subject = get_kb_item(string("ssl/nmap/",port,"/subject")))exit(0);

if(issuer == subject) {
  security_warning(port:port);
  exit(0);
}  

exit(0);
