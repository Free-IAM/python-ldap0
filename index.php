<!-- $Id: index.php,v 1.6 2000/08/19 06:19:45 leonard Exp $ -->
<?
	$thishref = "index";
	include("header.php");
?>
<HTML><HEAD>
	<TITLE>Python-LDAP</TITLE>
</HEAD>
<BODY>

<? menubar() ?>

<h1>Python-LDAP</h1>

<p>
This project provide an LDAP client API for 
<a href="http://www.python.org/">Python</a> in the spirit of 
<a href="http://mirror.aarnet.edu.au/rfc/rfc1823.txt">RFC1823</a>.
It includes
<ul>
<li> a Python module called <em>_ldapmodule</em> that wraps an LDAP C library,
	such as you can download from:
	<ul><li><a href="http://www.openldap.org/">OpenLDAP</a>
	    <li><a href="ftp://terminator.rs.itd.umich.edu/ldap/">UMich</a>
	    <li><a href="http://developer.netscape.com/tech/directory/"
								>Netscape</a>
	    <li><a href="http://www.mozilla.org/directory/csdk.html">Mozilla</a>
	    <li><a href="http://developer.novell.com/ndk/cldap.htm">Novell</a>
	</ul>
<li> an object-oriented API for X.500 directories
</ul>
</p>

<p>
You can:
<ul>
<li><a href="release.php">download a release</a>
<li><a href="docs.php">read documentation</a>
<li><a href="lists.php">join a mailing list</a>
</ul>
</p>

<p>
<img align=right alt="[SourceForge]" src="http://sourceforge.net/images/sflogo2-steel.png" width="43" height="21">
This project is hosted by 
<a href="http://sourceforge.net/">SourceForge</a> (thanks!)
<br>
You might also want to look at the SourceForge Python-LDAP
<a href="http://sourceforge.net/project/?group_id=2072">project information</a>.

<hr>
<i>$Id: index.php,v 1.6 2000/08/19 06:19:45 leonard Exp $</i>
</BODY>
</HTML>
