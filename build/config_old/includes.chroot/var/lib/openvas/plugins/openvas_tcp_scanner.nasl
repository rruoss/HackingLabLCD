###############################################################################
# OpenVAS Vulnerability Test
# $Id: openvas_tcp_scanner.nasl 13 2013-10-27 12:16:33Z jan $
#
# Wrapper for calling built-in NVT "openvas_tcp_scanner" which was previously
# a binary ".nes".
#
# Authors:
# Jan-Oliver Wagner <Jan-Oliver.Wagner@greenbone.net>
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
tag_summary = "This plugin is a classical TCP port scanner
It shall be reasonably quick even against a firewalled target.

Once a TCP connection is open, it grabs any available banner
for the service identification plugins

Note that TCP scanners are more intrusive than
SYN (half open) scanners.";

# If this function is defined we have a OpenVAS Version with
# builtin-plugins to replace .nes plugins.
# This wrapper has the NVT ID as the old .nes for consistency
# reason.
if (defined_func("plugin_run_openvas_tcp_scanner"))
{

if (description)
{
 script_id(10335);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-14 10:12:23 +0100 (Fri, 14 Jan 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("OpenVAS TCP scanner");

desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Look for open TCP ports & services banners");
 script_category(ACT_SCANNER);
 script_family("Port scanners");
 script_copyright("(C) 2004 Michel Arboi <mikhail@nessus.org>");

 script_dependencies("ping_host.nasl");

 script_add_preference(name: "Number of connections done in parallel : ",
   value: "6", type: "entry");
 script_add_preference(name: "Network connection timeout : ",
   value: "5", type: "entry");
 script_add_preference(name: "Network read/write timeout : ",
   value: "5", type: "entry");
 script_add_preference(name: "Wrapped service read timeout : ",
   value: "2", type: "entry");
 script_add_preference(name:"SSL certificate : ", type:"file", value:"");
 script_add_preference(name:"SSL private key : ", type:"file", value:"");
 script_add_preference(name:"PEM password : ", type:"password", value:"");
 script_add_preference(name:"CA file : ", type:"file", value:"");

 script_timeout(4*360);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

plugin_run_openvas_tcp_scanner();

}
