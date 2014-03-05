# OpenVAS Vulnerability Test
# $Id: webserver_favicon.nasl 17 2013-10-27 14:01:43Z jan $
#
# Identify software/infrastructure via favicon
#
# Authors:
# Javier Fernandez-Sanguino
# based on sample code written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (c) 2005 Javier Fernandez-Sanguino
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
#

include("revisions-lib.inc");
tag_summary = "The remote web server contains a graphic image that is prone to
information disclosure. 

Description :

The 'favicon.ico' file found on the remote web server belongs to a
popular webserver.  This may be used to fingerprint the web server.";

tag_solution = "Remove the 'favicon.ico' file or create a custom one for your site.";

# Favicons from OWASP Favicon project:
# http://www.owasp.org/index.php/Category:OWASP_Favicon_Database_Project
# awk -F':' '{print "server[\""$1"\"]=\""$2"\";"}' favicon-md5

    desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;
if(description) {
    script_id(20108); 
    script_version("$Revision: 17 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
    script_tag(name:"cvss_base", value:"2.1");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
    script_tag(name:"risk_factor", value:"Medium");
    name = "Fingerprint web server with favicon.ico";
    script_name(name);
    summary = "Attempt to fingerprint web server with favicon.ico";
    script_summary(summary);

    script_description(desc);

    script_category(ACT_GATHER_INFO);
    script_copyright("This script is Copyright (C) 2005 Javier Fernandez-Sanguino"); 
    family = "Web application abuses";
    script_family(family);
    script_dependencies("http_version.nasl");
    script_require_ports("Services/www", 80);
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}


# Script code starts here

# Requirements
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);


# Make the request
req = http_get(item:"/favicon.ico", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if ( res == NULL ) exit(0);
md5 = hexstr(MD5(res));

# Known favicons list:
# Google Web Server, should not be seen outside Google, and servers as
# a way to test the script
# Various popular CMS, Wikis, ...
server["6399cc480d494bf1fcd7d16c42b1c11b"]="penguin";
server["09b565a51e14b721a323f0ba44b2982a"]="Google web server";
server["506190fc55ceaa132f1bc305ed8472ca"]="SocialText";
server["2cc15cfae55e2bb2d85b57e5b5bc3371"]="PHPwiki (1.3.14) / gforge (4.6.99+svn6496) - wiki";
server["389a8816c5b87685de7d8d5fec96c85b"]="XOOPS cms";
server["f1876a80546b3986dbb79bad727b0374"]="NetScreen WebUI";
server["226ffc5e483b85ec261654fe255e60be"]="Netscape 4.1";
server["b25dbe60830705d98ba3aaf0568c456a"]="Netscape iPlanet 6.0";
server["41e2c893098b3ed9fc14b821a2e14e73"]="Netscape 6.0 (AOL)";
server["a28ebcac852795fe30d8e99a23d377c1"]="SunOne 6.1";
server["71e30c507ca3fa005e2d1322a5aa8fb2"]="Apache on Redhat";
server["d41d8cd98f00b204e9800998ecf8427e"]="Zero byte favicon";
server["dcea02a5797ce9e36f19b7590752563e"]="Parallels Plesk ";
server["6f767458b952d4755a795af0e4e0aa17"]="Yahoo!";
server["5b0e3b33aa166c88cee57f83de1d4e55"]="DotNetNuke (http";
server["7dbe9acc2ab6e64d59fa67637b1239df"]="Lotus-Domino";
server["fa54dbf2f61bd2e0188e47f5f578f736"]="Wordpress";
server["6cec5a9c106d45e458fc680f70df91b0"]="Wordpress - obsolete version";
server["81ed5fa6453cf406d1d82233ba355b9a"]="E-zekiel";
server["ecaa88f7fa0bf610a5a26cf545dcd3aa"]="3-byte invalid favicon";
server["c1201c47c81081c7f0930503cae7f71a"]="vBulletin forum";
server["edaaef7bbd3072a3a0c3fb3b29900bcb"]="Powered by Reynolds Web Solutions (Car sales CMS)";
server["d99217782f41e71bcaa8e663e6302473"]="Apache on Red Hat/Fedora";
server["a8fe5b8ae2c445a33ac41b33ccc9a120"]="Arris Touchstone Device";
server["d16a0da12074dae41980a6918d33f031"]="ST 605";
server["befcded36aec1e59ea624582fcb3225c"]="SpeedTouch";
server["e4a509e78afca846cd0e6c0672797de5"]="i3micro VRG";
server["3541a8ed03d7a4911679009961a82675"]="status.net";
server["fa2b274fab800af436ee688e97da4ac4"]="Etherpad";
server["83245b21512cc0a0e7a67c72c3a3f501"]="OpenXPKI";
server["85138f44d577b03dfc738d3f27e04992"]="Gitweb";
server["70625a6e60529a85cc51ad7da2d5580d"]="SSLstrip ";
server["99306a52c76e19e3c298a46616c5899c"]="aMule (2.2.2)";
server["31c16dd034e6985b4ba929e251200580"]="analog (6.0)";
server["2d4cca83cf14d1adae178ad013bdf65b"]="Ant docs manual (1.7.1)";
server["032ecc47c22a91e7f3f1d28a45d7f7bc"]="Ant docs (1.7.1) / libjakarta-poi-java (3.0.2)";
server["31aa07fe236ee504c890a61d1f7f0a97"]="apache2 (2.2.9) docs-manual";
server["c0c4e7c0ac4da24ab8fc842d7f96723c"]="xsp (1.9.1)";
server["d6923071afcee9cebcebc785da40b226"]="autopsy (2.08)";
server["7513f4cf4802f546518f26ab5cfa1cad"]="axyl (2.6.0)";
server["de68f0ad7b37001b8241bce3887593c7"]="b2evolution (2.4.2)";
server["140e3eb3e173bfb8d15778a578a213aa"]="bmpx (0.40.14)";
server["4f12cccd3c42a4a478f067337fe92794"]="cacti (0.8.7b)";
server["66b3119d379aee26ba668fef49188dd3"]="cakephp (1.2.0.7296-rc2)";
server["09f5ea65a2d31da8976b9b9fd2bf853c"]="caudium (1.4.12)";
server["f276b19aabcb4ae8cda4d22625c6735f"]="cgiirc (0.5.9)";
server["a18421fbf34123c03fb8b3082e9d33c8"]="chora2 (2.0.2) ";
server["23426658f03969934b758b7eb9e8f602"]="chronicle (2.9) theme-steve";
server["75069c2c6701b2be250c05ec494b1b31"]="chronicle (2.9) theme-blog.mail-scanning.com";
server["27c3b07523efd6c318a201cac58008ba"]="cimg (1.2.0.1) ";
server["ae59960e866e2730e99799ac034eacf7"]="webcit (7.37)";
server["2ab2aae806e8393b70970b2eaace82e0"]="couchdb (0.8.0-0.9.1)";
server["ddd76f1cfe31499ce3db6702991cbc45"]="cream (0.41)";
server["74120b5bbc7be340887466ff6cfe66c6"]="cups (1.3.9) - doc";
server["abeea75cf3c1bac42bbd0e96803c72b9"]="doc-iana-20080601";
server["3ef81fad2a3deaeb19f02c9cf67ed8eb"]="dokuwiki (0.0.20080505) ";
server["e6a9dc66179d8c9f34288b16a02f987e"]="drupal cms (5.10) ";
server["bba9f1c29f100d265865626541b20a50"]="dtc (0.28.10) ";
server["171429057ae2d6ad68e2cd6dcfd4adc1"]="ebug-http (0.31)";
server["f6e9339e652b8655d4e26f3e947cf212"]="egroupware (1.4.004-2)";
server["093551287f13e0ee3805fee23c6f0e12"]="freevo (1.8.1) ";
server["56753c5386a70edba6190d49252f00bb"]="gallery (1.5.8)";
server["54b299f2f1c8b56c8c495f2ded6e3e0b"]="garlic-doc (1.6) ";
server["857281e82ea34abbb79b9b9c752e33d2"]="gforge (4.6.99+svn6496) - webcalendar";
server["27a097ec0dbffb7db436384635d50415"]="gforge (4.6.99+svn6496) - images";
server["0e14c2f52b93613b5d1527802523b23f"]="gforge (4.6.99+svn6496) ";
server["c9339a2ecde0980f40ba22c2d237b94b"]="glpi (0.70.2)";
server["db1e3fe4a9ba1be201e913f9a401d794"]="gollem (1.0.3)";
server["921042508f011ae477d5d91b2a90d03f"]="gonzui (1.2+cvs20070129) ";
server["ecab73f909ddd28e482ababe810447c8"]="gosa (2.5.16.1)";
server["c16b0a5c9eb3bfd831349739d89704ec"]="gramps (3.0.1)";
server["63d5627fc659adfdd5b902ecafe9100f"]="gsoap (2.7.9l) ";
server["462794b1165c44409861fcad7e185631"]="hercules (3.05) ";
server["3995c585b76bd5aa67cb6385431d378a"]="horde-sam (0.1+cvs20080316) - silver";
server["ee3d6a9227e27a5bc72db3184dab8303"]="horde-sam (0.1+cvs20080316) - graphics";
server["7cc1a052c86cc3d487957f7092a6d8c3"]="horde (3.2.1) - graphics/tango";
server["5e99522b02f6ecadbb3665202357d775"]="hplip (2.8.7) - installer";
server["39308a30527336e59d1d166d48c7742c"]="hplip (2.8.7) - doc";
server["43d4aa56dc796067b442c95976a864fd"]="hunchentoot (0.15.7) ";
server["32bf63ac2d3cfe82425ce8836c9ce87c"]="ikiwiki (2.56ubuntu1)";
server["f567fd4927f9693a7a2d6cacf21b51b6"]="imp (4.1.6)";
server["919e132a62ea07fce13881470ba70293"]="ingo (1.1.5)";
server["ed7d5c39c69262f4ba95418d4f909b10"]="jetty (5.1.14)";
server["6900fab05a50a99d284405f46e5bc7f6"]="k3d (0.6.7.0) ";
server["24d1e355c00e79dc13b84d5455534fe7"]="kdelibs (3.5.10-4.1.4) ";
server["8ab2f1a55bcb0cac227828afd5927d39"]="kdenetwork (4.1.4)";
server["54667bea91124121e98da49e55244935"]="kolab-webadmin (2.1.0-20070510)";
server["a5b126cdeaa3081f77a22b3e43730942"]="kronolith (2.1.8)";
server["d00d85c8fb3a11170c1280c454398d51"]="ktorrent (3.1.2) ";
server["fa21ab1b1e1b4c9516afbd63e91275a9"]="lastfmproxy (1.3b) ";
server["663ee93a41000b8959d6145f0603f599"]="ldap-account-manager (2.3.0) ";
server["ea84a69cb146a947fac2ac7af3946297"]="boost (1.34.1) ";
server["eb3e307f44581916d9f1197df2fc9de3"]="flac (1.2.1) ";
server["669bc10baf11b43391294aac3e1b8c52"]="libitpp (4.0.4)";
server["b8fe2ec1fcc0477c0d0f00084d824071"]="lucene (2.3.2) ";
server["12225e325909cee70c31f5a7ab2ee194"]="ramaze-ruby (0.3.9.1) ";
server["6be5ebd07e37d0b415ec83396a077312"]="ramaze-ruby (0.3.9.1) - dispatcher";
server["20e208bb83f3eeed7c1aa8a6d9d3229d"]="libswarmcache-java (1.0RC2+cvs20071027)";
server["5f8b52715c08dfc7826dad181c71dec8"]="mahara (1.0.4)";
server["ebe293e1746858d2548bca99c43e4969"]="mantis (1.1.2)";
server["0d42576d625920bcd121261fc5a6230b"]="mathomatic (14.0.6)";
server["f972c37bf444fb1925a2c97812e2c1eb"]="mediatomb (0.11.0)";
server["f5f2df7eec0d1c3c10b58960f3f8fb26"]="mnemo (2.1.2) ";
server["933a83c6e9e47bd1e38424f3789d121d"]="moodle (1.8.2) ";
server["b6652d5d71f6f04a88a8443a8821510f"]="moodle (1.8.2) - theme/cornflower";
server["06b60d90ccfb79c2574c7fdc3ac23f05"]="movabletype-opensource (4.2~rc4)";
server["21d80d9730a56b26dc9d252ffabb2987"]="mythplugins (0.21.0+fixes18722) ";
server["81df3601d6dc13cbc6bd8212ef50dd29"]="nag (2.1.4)";
server["1c4201c7da53d6c7e48251d3a9680449"]="nagios (3.0.2)";
server["28015fcdf84ca0d7d382394a82396927"]="nanoblogger (3.3)";
server["868e7b460bba6fe29a37aa0ceff851ba"]="netmrg (0.20)";
server["0b2481ebc335a2d70fcf0cba0b3ce0fc"]="ntop (3.3)";
server["c30bf7e6d4afe1f02969e0f523d7a251"]="nulog (2.0)";
server["9a8035769d7a129b19feb275a33dc5b4"]="ocsinventory-server (1.01)";
server["75aeda7adbd012fa93c4ae80336b4f45"]="parrot (0.4.13) - docs";
server["70777a39f5d1de6d3873ffb309df35dd"]="pathological (1.1.3)";
server["82d746eb54b78b5449fbd583fc046ab2"]="perl-doc-html (5.10.0)";
server["90c244c893a963e3bb193d6043a347bd"]="phpgroupware (0.9.16.012) ";
server["4b30eec86e9910e663b5a9209e9593b6"]="phpldapadmin (1.1.0.5)";
server["02dd7453848213a7b5277556bcc46307"]="phpmyadmin (2.11.8.1) - pmd ";
server["d037ef2f629a22ddadcf438e6be7a325"]="phpmyadmin (2.11.8.1)";
server["8190ead2eb45952151ab5065d0e56381"]="pootle (1.1.0)";
server["ba84999dfc070065f37a082ab0e36017"]="prewikka (0.9.14)";
server["0f45c2c79ebe90d6491ddb111e810a56"]="python-cherrypy (2.3.0-3.0.2)";
server["e551b7017a9bd490fc5b76e833d689bf"]="moin (1.7.1)";
server["275e2e37fc7be50c1f03661ef8b6ce4f"]="myghty (1.1)";
server["68b329da9893e34099c7d8ad5cb9c940"]="myghty (1.1) - zblog ";
server["5488c1c8bf5a2264b8d4c8541e2d5ccd"]="turbogears (1.0.4.4) - genshi/elixir";
server["6927da350550f29bc641138825dff36f"]="python-werkzeug (0.3.1) - docs ";
server["e3f28aab904e9edfd015f64dc93d487d"]="python-werkzeug (0.3.1) - cupoftee-examples";
server["69f8a727f01a7e9b90a258bc30aaae6a"]="quantlib-refman-html (0.9.0)";
server["b01625f4aa4cd64a180e46ef78f34877"]="quickplot (0.8.13)";
server["af83bba99d82ea47ca9dafc8341ec110"]="qwik (0.8.4.4ubuntu2)";
server["e9469705a8ac323e403d74c11425a62b"]="roundcube (0.1.1)";
server["7f57bbd0956976e797b4e8eebdc6d733"]="selfhtml (8.1.1)";
server["69acfcb2659952bc37c54108d52fca70"]="solr (1.2.0) - docs";
server["ffc05799dee87a4f8901c458f7291d73"]="solr (1.2.0) - admin";
server["aa2253a32823c8a5cba8d479fecedd3a"]="sork-forwards-h3 (3.0.1)";
server["a2e38a3b0cdf875cd79017dcaf4f2b55"]="sork-passwd-h3 (3.0)";
server["cb740847c45ea3fbbd80308b9aa4530a"]="sork-vacation-h3 (3.0.1)";
server["7c7b66d305e9377fa1fce9f9a74464d9"]="spe (0.8.4.h)";
server["0e2503a23068aac350f16143d30a1273"]="sql-ledger (2.8.15)";
server["1fd3fafc1d461a3d19e91dbbba03d0aa"]="tea (17.6.1)";
server["4644f2d45601037b8423d45e13194c93"]="tomcat (5.5.26)";
server["1de863a5023e7e73f050a496e6b104ab"]="torrentflux (2.4)";
server["83dea3d5d8c6feddec84884522b61850"]="torrentflux (2.4) - themes/G4E/";
server["d1bc9681dce4ad805c17bd1f0f5cee97"]="torrentflux (2.4) - themes/BlueFlux/";
server["8d13927efb22bbe7237fa64e858bb523"]="transmission (1.34)";
server["5b015106854dc7be448c14b64867dfa5"]="tulip (3.0.0~B6)";
server["ff260e80f5f9ca4b779fbd34087f13cf"]="turba (2.1.7)";
server["e7fc436d0bf31500ced7a7143067c337"]="twiki (4.1.2) - logos/favicon.ico";
server["9789c9ab400ea0b9ca8fcbd9952133bd"]="twiki (4.1.2) - webpreferences ";
server["2b52c1344164d29dd8fb758db16aadb6"]="vdr-plugin-live (0.2.0)";
server["237f837bbc33cd98a9f47b20b284e2ad"]="vdradmin-am (3.6.1) ";
server["6f7e92fe7e6a62661ac2b41528a78fc6"]="vlc (0.9.4)";
server["2507c0b0a60ecdc816ba45482affaedf"]="webcheck (1.10.2.0) ";
server["ef5169b040925a716359d131afbea033"]="websvn (2.0) ";
server["f6d0a100b6dbeb5899f0975a1203fd85"]="witty (2.1.5)";
server["81feac35654318fb16d1a567b8b941e7"]="yaws (1.77)";
server["33b04fb9f2ec918f5f14b41527e77f6d"]="znc (0.058)";
server["6434232d43f27ef5462ba5ba345e03df"]="znc (0.058) - webadmin/skins/default";
server["e07c0775523271d629035dc8921dffc7"]="zoneminder (1.23.3)";
server["4eb846f1286ab4e7a399c851d7d84cca"]="plone cms (3.1.1)";
server["e298e00b2ff6340343ddf2fc6212010b"]="Nessus 4.2-4.2.1 scanner web interface";
server["240c36cd118aa1ff59986066f21015d4"]="LANCOM Systems";
server["ceb25c12c147093dc93ac8b2c18bebff"]="COMpact 5020 VoIP";
server["05656826682ab3147092991ef5de9ef3"]="RapidShare";

# Check the hash against what we know about.
if (server[md5]) {
  if (report_verbosity > 0) {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "The 'favico.ico' fingerprints this webserver as ", server[md5], "."
    );
  }
  else report = desc;

  security_warning(port:port, data:report);
  exit(0);
}


# This is a sample script to obtain the list of favicon files from a Webscarab
# directory. Can be useful to add new favicon after a pen-test:
# 
##!/bin/sh
#
#pwd=`pwd`
#find . -name "*response*" |
#while read file ; do
#	if grep -q "^Content-type: image/x-icon" $pwd/$file; then
#	# It's an ico file
#
#	server=`grep --binary-files=text "^Server" $pwd/$file`
#	size=`stat -c %B $pwd/$file`
#		if [ ! -n "$server" ] 
#		then
#			server=`echo $server | sed -e 's/Server: //'`
#		else
#			server="unknown"
#		fi
#	echo "$server,$file,$size"
#	fi
#done

