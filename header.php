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
?>
