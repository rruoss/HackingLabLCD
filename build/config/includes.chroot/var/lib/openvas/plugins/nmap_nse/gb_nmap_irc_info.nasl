###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_irc_info.nasl 10 2013-10-27 10:03:59Z jan $
#
# Wrapper for Nmap IRC Info NSE script.
#
# Authors:
# NSE-Script: Doug Hoyte
# NASL-Wrapper: Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# NASL-Wrapper: Copyright (c) 2010 Greenbone Networks GmbH (http://www.greenbone.net)
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
tag_summary = "This script attempts to gather information from an IRC server.

  This is a wrapper on the Nmap Security Scanner's (http://nmap.org) irc-info.nse.";


if(description)
{
  script_id(801800);
  script_version("$Revision: 10 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:03:59 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2011-01-20 07:52:11 +0100 (Thu, 20 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_name("Nmap NSE: IRC Info");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Gathers information from an IRC server");
  script_category(ACT_GATHER_INFO);
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");

  if(defined_func("script_mandatory_keys"))
  {
    script_mandatory_keys("Tools/Present/nmap");
    script_mandatory_keys("Tools/Launch/nmap_nse");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  }
  else
  {
    script_require_keys("Tools/Present/nmap");
    script_require_keys("Tools/Launch/nmap_nse");
  }
  exit(0);
}


## Required Keys
if((! get_kb_item("Tools/Present/nmap5.21") &&
   ! get_kb_item("Tools/Present/nmap5.51")) ||
   ! get_kb_item("Tools/Launch/nmap_nse")) {
 exit(0);
}

## Run nmap and Get the result
res = pread(cmd: "nmap", argv: make_list("nmap", "--script=irc-info.nse",
                                          get_host_ip()));
if(res)
{
  foreach line (split(res))
  {
    ## Get Port
    if(port = eregmatch(pattern:"^([0-9]+)/tcp",string:line))
    {
      ircPort = port[1];
      result = NULL;
      continue;
    }

    if(ereg(pattern:"^\|",string:line))
    {
      result += substr(chomp(line),2);
      if("irc-info" >< result)
      {
        msg = string('Result found by Nmap Security Scanner (irc-info.nse) ',
                     'http://nmap.org:\n\n', result);
        security_note(data:msg, port:ircPort);
      }
    }

    error = eregmatch(string:line, pattern:"^nmap: (.*)$");
    if (error) {
      msg = string('Nmap command failed with following error message:\n', line);
      log_message(data:msg);
    }
  }
}
else
{
  msg = string('Nmap command failed entirely:\n');
  log_message(data:msg);
}
