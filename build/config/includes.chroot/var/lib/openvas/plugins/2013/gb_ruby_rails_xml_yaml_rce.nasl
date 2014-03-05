###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_rails_xml_yaml_rce.nasl 11 2013-10-27 10:12:02Z jan $
#
# Ruby on Rails XML Processor YAML Deserialization RCE Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary commands.
  Impact Level: System/Application";

tag_affected = "Ruby on Rails before 2.3.15, 3.0.x before 3.0.19, 3.1.x before 3.1.10,
  and 3.2.x before 3.2.11";
tag_insight = "Flaw is due to an error when parsing XML parameters, which allows symbol
  and yaml types to be a part of the request and can be exploited to execute
  arbitrary commands.";
tag_solution = "Upgrade to Ruby on Rails 2.3.15, 3.0.19, 3.1.10, 3.2.11, or higher";
tag_summary = "The host is installed with Ruby on Rails and is prone to remote
  command execution vulnerability.";

if(description)
{
  script_id(802050);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57187);
  script_cve_id("CVE-2013-0156");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-18 11:03:52 +0530 (Fri, 18 Jan 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Ruby on Rails XML Processor YAML Deserialization RCE Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://osvdb.org/89026");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51753");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24019");
  script_xref(name : "URL" , value : "http://www.insinuator.net/2013/01/rails-yaml");
  script_xref(name : "URL" , value : "http://ronin-ruby.github.com/blog/2013/01/09/rails-pocs.html");
  script_xref(name : "URL" , value : "http://blog.codeclimate.com/blog/2013/01/10/rails-remote-code-execution-vulnerability-explained");
  script_xref(name : "URL" , value : "https://community.rapid7.com/community/metasploit/blog/2013/01/09/serialization-mischief-in-ruby-land-cve-2013-0156");

  script_description(desc);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check for RCE vulnerability in Ruby on Rails");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_require_ports("Services/www", 3000);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable initialisation
res = "";
host = "";
req1 = "";
req2 = "";
req3 = "";
res2 = "";
res3 = "";
railsPort = "";
post_data1 = "";
post_data2 = "";
post_data3 = "";

## Check for default port
railsPort = get_http_port(default:3000);
if(!railsPort){
  railsPort = 80;
}

## Check port state
if(!get_port_state(railsPort)){
  exit(0);
}

## Get host name
host = get_host_name();
if(!host){
  exit(0);
}

## Not using detect script as "rails/info/properties" works only in
## development and test modes and recently it is shifted to local for
## development and test as well.
## As this vulnerability is very critical, iterating over possible paths

## Normally the path will be "/", but adding few more to it
dirs = make_list("/", "/rails", "/ror", "/framework", "/posts");

foreach dir (dirs)
{

  ## Intitial request
  req_common = string("POST ", dir , " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "User-Agent: OpenVAS Agent\r\n",
                      "Content-Type: application/xml\r\n");
  post_data1 = string('<?xml version="1.0" encoding="UTF-8"?>\r\n',
                      '<probe type="string"><![CDATA[\r\n', 'hello\r\n',
                      ']]></probe>');
  req1 = string(req_common, "Content-Length: ", strlen(post_data1),
                                            "\r\n\r\n", post_data1);
  res1 = http_send_recv(port:railsPort, data:req1);

  ## Ignore if http status code starts with 4 or 5
  if(egrep(pattern:"^HTTP/1.. (4|5)[0-9][0-9] ", string:res1)){
    continue;
  }

  ## Construct initial XML request
  post_data2 = string('<?xml version="1.0" encoding="UTF-8"?>\r\n',
                      '<probe type="yaml"><![CDATA[\r\n',
                      '--- !ruby/object:Time {}\r\n','\r\n', ']]></probe>');
  req2 = string(req_common, "Content-Length: ", strlen(post_data2),
                                             "\r\n\r\n", post_data2);
  res2 = http_send_recv(port:railsPort, data:req2);

  ## Continue if http status code starts with 2 or 3
  if(egrep(pattern:"^HTTP/1.. (2|3)[0-9][0-9] ", string:res2))
  {
    ## Construct invalid YAML request
    post_data3 = string('<?xml version="1.0" encoding="UTF-8"?>\r\n',
                        '<probe type="yaml"><![CDATA[\r\n',
                        '--- !ruby/object:\x00\r\n', ']]></probe>');
    req3 = string(req_common, "Content-Length: ", strlen(post_data3), "\r\n\r\n", post_data3);
    res3 = http_send_recv(port:railsPort, data:req3);

    ## Extract http response code
    res2_code = eregmatch(pattern:"^HTTP/1.. ([0-9][0-9][0-9]) ", string:res2);
    res3_code = eregmatch(pattern:"^HTTP/1.. ([0-9][0-9][0-9]) ", string:res3);

    ## Vulnerable if res2 and res3 http codes are not same
    ## and http response code should not be 200
    if(res2_code[1] && res3_code[1] && res2_code[1] != res3_code[1] &&
      !(egrep(pattern:"^HTTP/1.. 200 ", string:res3)))
    {
        security_hole(railsPort);
        exit(0);
    }
  }
}
