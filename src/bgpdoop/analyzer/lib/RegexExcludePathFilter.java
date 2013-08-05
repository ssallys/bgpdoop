package bgpdoop.analyzer.lib;


import org.apache.hadoop.fs.PathFilter;

public class RegexExcludePathFilter implements PathFilter {
	private final String regex = "^.*/bview.*$";

//	private final String regex = "^.*";
	
	public boolean accept(org.apache.hadoop.fs.Path path) {
		// TODO Auto-generated method stub
		return !path.toString().matches(regex);
	}
}