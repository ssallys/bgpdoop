package bgpdoop.runner;

import org.apache.hadoop.fs.Path;

import bgpdoop.analyzer.BgpAddressSpaceCountUp;
import bgpdoop.analyzer.BgpBasicStats_inMapperCombiner;
import bgpdoop.analyzer.BgpDiffPathCountUp;
import bgpdoop.analyzer.BgpMrtCapacityChecker;
import bgpdoop.analyzer.BgpDpathSpathCountUp;
import bgpdoop.analyzer.BgpBasicStats;
import bgpdoop.analyzer.BgpdumpParser_RIB;
import bgpdoop.analyzer.BgpdumpParser_Update;
import bgpdoop.analyzer.BgpMessageCountUp;
import bgpdoop.analyzer.BgpStatsAnalyzer;
import bgpdoop.analyzer.HijackDetector;
import bgpdoop.analyzer.asmap.AS_Prefix_Mapper;
import bgpdoop.analyzer.graph.RIB_Graph_AdjList;
import bgpdoop.analyzer.hive.HiveJdbcClient;
import bgpdoop.analyzer.lib.TopN;

public class Runner {
	static final String INPATH = "tstat_in";
	public static void main(String[] args) throws Exception{

		String inPathStr = new String();
		String tablename = new String();
		char job = 's';
		int fieldNo = 0;
		int k = 0;
		char argtype = 0;
		int reduces = 1;
		String month = "2012-05";
		
		
		/* Argument Parsing */
		int i = 0;
		while(i<args.length){
			if(args[i].startsWith("-")){
				
				argtype = args[i].charAt(1);
				switch (argtype){					
				case 'R': case 'r':
					inPathStr += args[i].substring(2);
					break;							
				case 'T': case 't':
					tablename += args[i].substring(2);
					break;						
				case 'N': case 'n':
					reduces = Integer.parseInt(args[i].substring(2).trim());
					break;						
				case 'K': case 'k':
					k = Integer.parseInt(args[i].substring(2).trim());
					break;											
				case 'J': case 'j':
					job = args[i].substring(2).trim().charAt(0);
					break;	
				}					
			}
			else{
				switch (argtype){									
				case 'R': case 'r':
					inPathStr += args[i].substring(2);
					break;							
				case 'T': case 't':
					tablename += args[i].substring(2);
					break;						
				case 'J': case 'j':
					job = args[i].substring(2).trim().charAt(0);
					break;		
				}
			}
			i++;
		}
		switch(job){	
		
			case 't':	// parse
				System.out.println("test called.");
				new Test().run(inPathStr);
			break;
				
			case 'u':	// parse
				System.out.println("Bgp Update Message parser called.");
				BgpdumpParser_Update bmp = new BgpdumpParser_Update();
				bmp.analysis(inPathStr, reduces);
		//			HiveJdbcClient.loadUserBehavior();
				break;
				
			case 'r':	// parse
				System.out.println("Bgp RIB parser called.");
				BgpdumpParser_RIB brp = new BgpdumpParser_RIB();
				brp.analysis(inPathStr, reduces);
		//			HiveJdbcClient.loadUserBehavior();
				break;
/*				
			case 'h':	// hijack
				System.out.println("Bgp Hijack detector called.");
				HijackDetector hdetector = new HijackDetector();
				hdetector.analysis(inPathStr, reduces, tablename);
		//			HiveJdbcClient.loadUserBehavior();
				break;
				
			case 'c':
				System.out.println("BasicStatistics inmappercombiner CountUp called.");
				BgpBasicStats_inMapperCombiner bu = new BgpBasicStats_inMapperCombiner();
				bu.analysis(inPathStr, new Path("as_name"), reduces); // inPathStr -> rrc00/2012.02
				new HiveJdbcClient().load_data("msgcount", inPathStr); 	// inPathStr -> rrc00/2012.02
				break;		
*/				
			case 'C':	/* withdraw, announce count per prefix */
				System.out.println("BasicStatistics CountUp called.");
				BgpBasicStats bb= new BgpBasicStats();
				bb.analysis(inPathStr, new Path("as_name"), reduces); 
				break;	
/*				
			case 'd':	// DiffPath count up
				System.out.println("Bgp DiffPath called.");
				BgpDiffPathCountUp diff = new BgpDiffPathCountUp();
				diff.analysis(inPathStr, reduces);
				//	HiveJdbcClient.loadUserBehavior();
				break;		
								
			case 'D':	// dpath & spath count up
				System.out.println("Bgp Message Counter called.");
				BgpDpathSpathCountUp bw = new BgpDpathSpathCountUp();
				bw.analysis(new Path(inPathStr), new Path("as_name"));
				break;		
				
			case 's':	// address space count up
				System.out.println("Bgp Address Space Counter called.");
				BgpAddressSpaceCountUp as = new BgpAddressSpaceCountUp();
				as.analysis(new Path(inPathStr), new Path("as_name"));
				break;	
*/				
			case 'f':	// basic statistics
				System.out.println("BgpStats Analyzer called.");
				BgpStatsAnalyzer bs = new BgpStatsAnalyzer();
				bs.analysis(new Path(inPathStr), new Path("as_name"));
				break;	
/*								
			case 'n':	// Tcp topN
				System.out.println("TopN called.");
				TopN topN = new TopN();
				topN.startTopN(new Path(inPathStr), new Path(inPathStr+"_out"), fieldNo, k);
				break;
*/				
			case 'g':	// graph
				System.out.println("Graph called.");
				RIB_Graph_AdjList graph = new RIB_Graph_AdjList();
				graph.analysis(inPathStr, reduces);
				break;
				
			case 'm':	// asmap
				System.out.println("ASMap called.");
				AS_Prefix_Mapper asmap = new AS_Prefix_Mapper();
				asmap.analysis(inPathStr, reduces);
				break;
/*				
			case 'v':	// Mrt Volume
				System.out.println("Volume checker called.");
				BgpMrtCapacityChecker vc = new BgpMrtCapacityChecker();
				vc.analysis(inPathStr);
				break;		
				
			case 'o':	// basic count up
				System.out.println("Bgp Message Counter called.");
				BgpMessageCountUp bc = new BgpMessageCountUp();
				bc.analysis(inPathStr, new Path("as_name"), reduces);
//					HiveJdbcClient.loadUserBehavior();
				break;	
				
			case 'l':
				System.out.println("load msgcount to Hive.");
				
				new HiveJdbcClient().load_data(tablename, inPathStr); 	// inPathStr -> rrc00/2012.02
				break;	
*/				
		}
	}
}