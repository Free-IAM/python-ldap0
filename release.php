<!-- $Id: release.php,v 1.16 2000/12/10 12:54:55 leonard Exp $ -->
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
	    <th>Build OS</th>
	    <th>Python</th>
	    <th>LDAP lib</th>
	    <th>Notes</th>
	</tr>
	<!--	   filename, version, OS, Python, LDAP -->

	<? binrelease("python-ldap-1.10alpha3-OpenBSD-i386.tgz", 
		      "1.10alpha3",
		      "OpenBSD/i386 2.7",
		      "1.6a2",
		      "OpenLDAP 1.2.11",
		      "pkg_add") ?>
	<? binrelease("python-ldap-1.10alpha3-1.i386.rpm", 
		      "1.10alpha3",
		      "Linux/x86 2.2.14-5.0.14smp",
		      "1.5.2",
		      "OpenLDAP 1.2.11",
		      "rpm") ?>
	</table>
    </td>
</tr>
</table>

<dl>
<dt>CVS
<dd>The CVS source repository can be accessed using pserver or ssh protocols at
<ul><li><i>:pserver:anonymous@cvs.python-ldap.sourceforge.net:/cvsroot/python-ldap</i> (empty password)
<li><i>:ext:username@cvs.python-ldap.sourceforge.net:/cvsroot/python-ldap</i> 
 (for sourceforge developers)
</ul>

</dl>

<hr>
<i>$Id: release.php,v 1.16 2000/12/10 12:54:55 leonard Exp $</i>
</BODY>
</HTML>
