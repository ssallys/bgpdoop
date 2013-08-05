package bgpdoop.analyzer;

import java.io.IOException;
import java.util.Calendar;
import java.util.TreeMap;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.PathFilter;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.IntWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.NullWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.mapreduce.Reducer;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;

import bgpdoop.analyzer.BgpBasicStats_inMapperCombiner.BgpMessageCnt_MapperCombiner.CntStats;
import bgpdoop.analyzer.lib.Bgp4mp_Message;
import bgpdoop.analyzer.lib.Bgp4mp_State;
import bgpdoop.analyzer.lib.MrtFormat;
import bgpdoop.analyzer.lib.Prefix;
import bgpdoop.analyzer.lib.Tabledump_Mrtd;
import bgpdoop.analyzer.lib.Tabledumpv2_PeerEntry;
import bgpdoop.analyzer.lib.Tabledumpv2_RibEntry;
import bgpdoop.hadoop.mapreduce.lib.input.BgpInputFormat;
import p3.hadoop.common.util.EZBytes;

/**
 * 
 * @author yhlee of the Chungnam National University
 *  ssallys@naver.com
 */
public class BgpBasicStats {
		
	/*******************************************
		BGP Stats
	*******************************************/
	public static class BgpMessageCnt_Mapper extends Mapper<LongWritable, BytesWritable, Text, Text>{
		
		EZBytes eb;
		MrtFormat mrt;
		Bgp4mp_Message bm;
		Bgp4mp_State bs;
		Tabledumpv2_PeerEntry pe;
		Tabledumpv2_RibEntry re;
		Tabledump_Mrtd mt;
		int pos;
		int cnt=0;
		int asn_len = 0;
		
		String date = null;
		String month = null;
		Calendar cal;
		
	    private final static int zero = 0; 
	    private final static int one = 1;
	    private final static String delimiter = "|"; 

	    StringBuilder sb;
	    CntStats cs;
		String as;
	    
	    class CntStats{	    	
	    	
	    	String as;
	    	Long withdrawalCnt;
			Long announceCnt;	  
		
			public CntStats(String as , Long withdrawalCnt, Long announceCnt) {
				super();
				this.as = as;
				this.withdrawalCnt = withdrawalCnt;
				this.announceCnt = announceCnt;
			}
			public String getAs() {
				return as;
			}
			public void setAs(String as) {
				this.as = as;
			}
			public Long getWithdrawalCnt() {
				return withdrawalCnt;
			}
			public void setWithdrawalCnt(Long withdrawalCnt) {
				this.withdrawalCnt = withdrawalCnt;
			}
			public Long getAnnounceCnt() {
				return announceCnt;
			}
			public void setAnnounceCnt(Long announceCnt) {
				this.announceCnt = announceCnt;
			} 
			public void addWithdrawalCnt() {
				this.withdrawalCnt++;
			}
			public void addAnnounceCnt() {
				this.announceCnt++;
			}	
			public void appendAs(String as) {
				// TODO Auto-generated method stub
				this.as= this.as + ","+ as;
			}
	    	@Override
			public String toString() {
				return delimiter + as + delimiter + withdrawalCnt + delimiter + announceCnt;
			}
	    }
	    
	    public void map(LongWritable key, BytesWritable value, Context context) throws IOException, InterruptedException {	

			byte[] value_bytes = value.getBytes();
			eb = new EZBytes(value_bytes.length);
			eb.PutBytes(value_bytes, 0, value_bytes.length);
			pos=0;
			mrt = new MrtFormat();
			
			try{
				pos += mrt.parseMrtHeader(eb.GetBytes(pos,12));					
				switch (mrt.type){						
				/* BGP4MP */	
				case MrtFormat.BGPDUMP_TYPE_BGP4MP:
					
					cal = Calendar.getInstance();
					cal.setTimeInMillis(mrt.timestamp*1000);
					date = String.format("%1$tY.%1$tm.%1$td.%1$tH%1$tM", cal);
					month = String.format("%1$tY.%1$tm", cal);
					
					bm = new Bgp4mp_Message();
					boolean res = false;
					
					switch(mrt.subtype){				
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_MESSAGE:
						res = bm.parseMessage(eb.GetBytes(pos), 2);						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_MESSAGE_AS4:
						res = bm.parseMessage(eb.GetBytes(pos), 4);
						break;									
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_ENTRY:
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_SNAPSHOT:
						break;	
					default:	
						break;
					}
					
					if(res){
						
						if(bm.attribute.aspaths.aspaths.toString().trim().lastIndexOf(" ")>0)
							as = bm.attribute.aspaths.aspaths.substring(bm.attribute.aspaths.aspaths.toString().trim().lastIndexOf(" ")+1);
						else
							as = bm.attribute.aspaths.aspaths.toString();
					
						/* withdrawal count */
						String k_heap = null;
						
						for(Prefix prefix: bm.withdraw){
							sb = new StringBuilder();
							sb.append(date.substring(0, date.length()-2)).append(delimiter)
							.append(prefix.prefix+"/"+prefix.prefix_len).append(delimiter);		
							
							context.write(new Text("monitor00" + delimiter + month + delimiter + sb.substring(0, sb.lastIndexOf(delimiter))+delimiter+"peer"+bm.peer_as+delimiter)
				    			, new Text(as + delimiter + one + delimiter + zero));
						}

						/* announcement count */
						for(Prefix prefix: bm.announce){
							sb = new StringBuilder();
							sb.append(date.substring(0, date.length()-1)).append(delimiter)
							.append(prefix.prefix+"/"+prefix.prefix_len).append(delimiter);		
							
							context.write(new Text("monitor00" + delimiter + month + delimiter + sb.substring(0, sb.lastIndexOf(delimiter))+delimiter+"peer"+bm.peer_as+delimiter)
			    			, new Text(as + delimiter + zero + delimiter + one));
						}
						
					}				
					break;
				default:
				}
				
			} catch (NumberFormatException e) {							  
			}								
		}		
		public void close(){
		}				
	}
	
	
	public static class BgpMessageCnt_Combiner extends Reducer<Text, Text, Text, Text> {
		
		int sumWithdraw;
		int sumAnnounce;
		String[] line = null;
		String as = null;
		
	    private final static String delimiter = "|"; 

		 public void reduce(Text key, Iterable<Text> values, Context context) 
			      throws IOException, InterruptedException {
			 
			 sumWithdraw = 0;
			 sumAnnounce = 0;
			 as = new String();
			 
			 for (Text val : values) {
				 line = val.toString().split("\\|",3);
				 
				 if(as!=null) as += ",";
				 else as = new String();
				 as += line[0];
				 
				 sumWithdraw += Integer.parseInt(line[1]);
				 sumAnnounce += Integer.parseInt(line[2]);
			 }
			 context.write(key, new Text(as+delimiter + sumWithdraw + delimiter + sumAnnounce));
		 }
	}
	
	public static class BgpMessageCnt_Reducer extends Reducer<Text, Text, NullWritable, Text> {
		
		int sumWithdraw;
		int sumAnnounce;
		String[] line = null;
		String as = null;
		
	    private final static String delimiter = "|"; 

		 public void reduce(Text key, Iterable<Text> values, Context context) 
			      throws IOException, InterruptedException {
			 
			 sumWithdraw = 0;
			 sumAnnounce = 0;
			 		 
			 for (Text val : values) {
				 
				 line = val.toString().split("\\|",3);
				 
				 if(as!=null) as += ",";
				 else as = new String();
				 as += line[0];
				 
				 sumWithdraw += Integer.parseInt(line[1]);
				 sumAnnounce += Integer.parseInt(line[2]);
			 }
			 context.write(NullWritable.get(), new Text(key.toString()+as+delimiter + sumWithdraw + delimiter + sumAnnounce));
		 }
	}
		
	private Job getJobConf(Job	job, String strInPath, Path bgpPath, Path asnPath, int reduces) throws IOException{
		
		Path outPath = new Path(strInPath);			
		job.setJobName(strInPath); 
		job.setJarByClass(BgpBasicStats.class);   
		job.setNumReduceTasks(reduces);   
		
		job.setInputFormatClass(BgpInputFormat.class);
		job.setOutputFormatClass(TextOutputFormat.class);
		job.setMapOutputKeyClass(Text.class);
		job.setMapOutputValueClass(Text.class);	
		
		job.setOutputKeyClass(NullWritable.class);
		job.setOutputValueClass(Text.class);	     

		FileInputFormat.addInputPath(job, bgpPath);
        FileOutputFormat.setOutputPath(job, outPath);
        
		job.setMapperClass(BgpMessageCnt_Mapper.class);     
		job.setCombinerClass(BgpMessageCnt_Combiner.class);
		job.setReducerClass(BgpMessageCnt_Reducer.class);
		
		return job;
	}
		
	public boolean analysis(String strPath, Path asnPath, int reduces) throws IOException, ClassNotFoundException, InterruptedException {
		
		Configuration conf = null;
		Job job = null;	
		Path bgpPath = null;
		
        String[] strs = strPath.split("\\/");
        if (strs.length<2) return false;
    
		if(strPath.endsWith(".gz") || strPath.endsWith(".bz2"))
			bgpPath = new Path(strPath);
		else
			bgpPath = new Path(strPath+"/UPDATES");
        	      
	    String monitor = strs[0];//strPath.substring(strPath.indexOf("\\/")+1); // 2012.02
        String month = strs[1];
		
		conf = new Configuration();
		job = new Job(conf);
			
		getJobConf(job, "msgcount/"+monitor+"/"+month, bgpPath, asnPath, reduces);  
		FileSystem fs = FileSystem.get(conf);	
		// delete any output that might exist from a previous run of this job
		if (fs.exists(FileOutputFormat.getOutputPath(job))) {
			fs.delete(FileOutputFormat.getOutputPath(job), true);
		}		
		job.waitForCompletion(true);

		return true;
		
	}
	
	public class RegexExcludePathFilter implements PathFilter {
		private final String regex = "^.*/?view.*$";
		
		public boolean accept(org.apache.hadoop.fs.Path path) {
			// TODO Auto-generated method stub
			return !path.toString().matches(regex);
		}
	}
}
