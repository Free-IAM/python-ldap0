<!-- $Id: release.php,v 1.10 2000/08/16 12:12:43 leonard Exp $ -->
<?
	$thishref = "release";
	include("header.php");
?>
<HTML><HEAD>
	<TITLE>Python-LDAP: Download</TITLE>
</HEAD>
<BODY>

<? menubar() ?>

<h1>Python-LDAP: Download</h1>

<table border=0>
<tr><th> Source </th>
    <th> Binary </th>
</tr><tr valign=top>
    <td>
	<table border=1>
	<tr><th>Version</th></tr>
	<? srcrelease("python-ldap-1.10alpha-src.tar.gz",    "1.10alpha") ?>
	<? srcrelease("python-ldap-1.10alpha2-src.tar.gz",   "1.10alpha2") ?>
	<? srcrelease("python-ldap-1.10alpha3-src.tar.gz",   "1.10alpha3") ?>
	</table>
    </td>
    <td>
	<table border=1>
	<tr><th>Version</th>
	    <th>OS</th>
	    <th>Python</th>
	    <th>LDAP</th>
	    <th>Notes</th>
	</tr>
	<!--	   filename, version, OS, Python, LDAP -->
	<? if (0) binrelease("python-ldap-1.10alpha-linux-x86.rpm", 
		      "1.10alpha",
		      "Linux/x86 2.2.14-5.0.14smp",
		      "1.5.2",
		      "OpenLDAP 1.2.11",
		      "") ?>
	<? binrelease("python-ldap-1.10alpha-OpenBSD-i386.tgz", 
		      "1.10alpha",
		      "OpenBSD/i386 2.7",
		      "1.6a2",
		      "OpenLDAP 1.2.11",
		      "") ?>
	</table>
    </td>
</tr>
</table>

<dl>
<dt>CVS
<dd>The CVS source repository can be accessed using pserver or ssh protocols at
<i>cvs.python-ldap.sourceforge.net:/cvsroot/python-ldap</i>
(username &quot;<tt>anonymous</tt>&quot;, password &quot;<tt></tt>&quot;.)

<dt>Historic
<dd>Some historic releases for <i>ldapmodule</i> may be available from
    <a href="http://www.csee.uq.edu.au/~leonard/dc-prj/ldapmodule/">David Leonard's ldapmodule page</a>.
</dl>

<hr>
<i>$Id: release.php,v 1.10 2000/08/16 12:12:43 leonard Exp $</i>
</BODY>
</HTML>
