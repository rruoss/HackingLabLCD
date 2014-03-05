###############################################################################
# OpenVAS Vulnerability Test
# $Id: synscan.nasl 13 2013-10-27 12:16:33Z jan $
#
# Wrapper for calling built-in NVT "synscan" which was previously
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
tag_summary = "This plugins performs a supposedly fast SYN port scan.
It does so by computing the RTT (round trip time) of the packets
coming back and forth between the openvassd host and the target,
then it uses that to quickly send SYN packets to the remote host.";

# If this function is defined we have a OpenVAS Version with
# builtin-plugins to replace .nes plugins.
# This wrapper has them NVT ID as the old .nes for consistency
# reason.
if (defined_func("plugin_run_synscan"))
{

if (description)
{
 script_id(11219);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-14 10:12:23 +0100 (Fri, 14 Jan 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("SYN Scan");

desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Performs a TCP SYN scan");
 script_category(ACT_SCANNER);
 script_family("Port scanners");
 script_copyright("Copyright (C) Renaud Deraison <deraison@cvs.nessus.org>");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

plugin_run_synscan();

}
