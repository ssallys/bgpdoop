package bgpdoop.analyzer.lib;

public class Prefix{
	public int prefix_len;
	public String prefix;
			
	public Prefix() {
		super();
		// TODO Auto-generated constructor stub
	}

	public Prefix(int prefix_len, String prefix) {
		super();
		this.prefix_len = prefix_len;
		this.prefix = prefix;
	}
}
