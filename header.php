<?
	$pages = array(
		"index" =>	"Home",
		"lists" =>	"Lists",
		"release" =>	"Download"
	);

	function menubar() {
		global $thishref, $pages;
		$delim = "<p align=right>[";
		reset ($pages);
		while (list($href,$title) = each($pages)) {
			print $delim;
			if ($href != $thishref) {
				print "<a href=\"" . $href . ".php\">" .
					$title . "</a>";
			} else {
				print $title;
			}
			$delim = "|";
		}
		if ($delim == "|") {
			print "]</p>";
		}
	}

	$release_root = "ftp://python-ldap.sourceforge.net/pub/python-ldap";

	function release($name, $desc, $vers) {
		print "<tr><td><a href="$release_root/$name">$name</a></td>
			   <td>$desc</td>
			   <td>$vers</td></tr>\n";
	}
?>
