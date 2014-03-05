# OpenVAS Vulnerability Test
# $Id: iis_unc_mapped_virt_host_vuln.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Microsoft IIS UNC Mapped Virtual Host Vulnerability
#
# Authors:
# tony@libpcap.net, http://libpcap.net
#
# Copyright:
# Copyright (C) 2001 tony@libpcap.net
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

include("revisions-lib.inc");
tag_summary = "Your IIS webserver allows the retrieval of ASP/HTR source code.

An attacker can use this vulnerability to see how your
pages interact and find holes in them to exploit.";

if(description) {
  script_id(11443);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1081);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2000-0246");

  name = "Microsoft IIS UNC Mapped Virtual Host Vulnerability";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);

  summary = "Checks IIS for .ASP/.HTR backslash vulnerability.";
  script_summary(summary);
  script_copyright("Copyright (C) 2001 tony@libpcap.net");
  script_category(ACT_GATHER_INFO);

  family = "Web Servers";
  script_family(family);

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if(get_port_state(port)) {
  # common ASP files
  f[0] = "/index.asp%5C";
  f[1] = "/default.asp%5C";
  f[2] = "/login.asp%5C";
  
  files = get_kb_list(string("www/", port, "/content/extensions/asp"));
  if(!isnull(files)){
 	files = make_list(files);
	f[3] = files[0] + "%5C";
	}

  for(i = 0; f[i]; i = i + 1) {
    req = http_get(item:f[i], port:port);
    h = http_keepalive_send_recv(port:port, data:req);
    if( h == NULL ) exit(0);
    
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:h) &&
       "Content-Type: application/octet-stream" >< r) {
      security_warning(port);
      exit(0);
    }
  }
}
