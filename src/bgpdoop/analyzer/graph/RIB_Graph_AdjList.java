package bgpdoop.analyzer.graph;

import java.io.IOException;
import java.util.Calendar;
import java.util.HashMap;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.NullWritable;
import org.apache.hadoop.io.Text;

import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.mapreduce.Reducer;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;

import bgpdoop.analyzer.lib.Bgp4mp_Message;
import bgpdoop.analyzer.lib.Bgp4mp_State;
import bgpdoop.analyzer.lib.MrtFormat;
import bgpdoop.analyzer.lib.Tabledump_Mrtd;
import bgpdoop.analyzer.lib.Tabledumpv2_PeerEntry;
import bgpdoop.analyzer.lib.Tabledumpv2_RibEntry;
import bgpdoop.analyzer.lib.Tabledumpv2_PeerEntry.PeerEntry;
import bgpdoop.analyzer.lib.Tabledumpv2_RibEntry.RIBEntry;
import bgpdoop.hadoop.mapreduce.lib.input.BgpInputFormat;
import p3.hadoop.common.util.EZBytes;

/**
 * 
 * @author yhlee in Chungnam National University
 *  ssallys@naver.com
 */
public class RIB_Graph_AdjList {
		
	/*******************************************
			BGP Stats
	*******************************************/
	public static class AdjList_Mapper extends Mapper<LongWritable, BytesWritable, Text, Text>{
		
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
		HashMap<Integer, Long> peerEntries=null;
		
		String date = null;
		long datestamp = 0;
		Calendar cal;
		
		boolean res = false;
		static final String delimiter=",";

	    public void map(LongWritable key, BytesWritable value, Context context) 
	    		throws IOException, InterruptedException {	

			byte[] value_bytes = value.getBytes();
			eb = new EZBytes(value_bytes.length);
			eb.PutBytes(value_bytes, 0, value_bytes.length);
			pos=0;
			mrt = new MrtFormat();
			
			try{
				pos += mrt.parseMrtHeader(eb.GetBytes(pos,12));		
		
				switch (mrt.type){					
				/* TABLE_DUMP */
				case MrtFormat.BGPDUMP_TYPE_MRTD_TABLE_DUMP:	
					mt = new Tabledump_Mrtd();
					
					switch(mrt.subtype){
					case MrtFormat.BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP: 
						res = mt.parseRibEntry(eb.GetBytes(pos), 4, 2);
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP_32BIT_AS:
						res = mt.parseRibEntry(eb.GetBytes(pos), 4, 4);
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP6: 
						res = mt.parseRibEntry(eb.GetBytes(pos), 16, 2);
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP6_32BIT_AS:
						res = mt.parseRibEntry(eb.GetBytes(pos), 16, 4);
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_GENERIC:
						return;
					}
					
					if(res){
						String[] aspaths = mt.attribute.aspaths.aspaths.toString().trim().split("\\s");
						String prev_as = null;
						for(String aspath : aspaths){
							if(!aspath.startsWith("AS")) continue;
							if(prev_as==null) 
								prev_as = aspath;
							else{
								context.write(new Text(prev_as), new Text(delimiter+aspath));
								prev_as = aspath;
							}
						}	
//						context.write(new TextPair(new Text(prev_as), new Text(mt.prefix+"/"+mt.prefixLen)), ONE);						
					}
					break;
										
				/* TABLE_DUMP_V2 */
				case MrtFormat.BGPDUMP_TYPE_TABLE_DUMP_V2:				
					switch(mrt.subtype){
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_PEER_INDEX_TABLE:
						pe = new Tabledumpv2_PeerEntry();
						if((asn_len = pe.parsePIT(eb.GetBytes(pos)))>0){
							for(PeerEntry el : pe.peerEntries)
								context.write(new Text("AS_center"), new Text(delimiter+"AS"+String.valueOf(el.pAS)));
						}
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV4_UNICAST: case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV4_MULTICAST:
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV6_UNICAST: case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV6_MULTICAST:
						re = new Tabledumpv2_RibEntry();
						if(re.parseRibEntry(eb.GetBytes(pos), asn_len)>0){	  
							if(re.entryCnt>0)				
								for(RIBEntry entry:re.ribEntries){
									if(re.prefix != null && entry.attribute!=null){
										String[] aspaths = entry.attribute.aspaths.aspaths.toString().trim().split("\\s");
										String prev_as = null;
										for(String aspath:aspaths){
											if(!aspath.startsWith("AS")) continue;
											if(prev_as==null) 
												prev_as = aspath;
											else{
												context.write(new Text(prev_as), new Text(delimiter+aspath));
												prev_as = aspath;
											}
										}
//										context.write(new TextPair(new Text(prev_as), new Text(re.prefix+"/"+re.prefixLen)), ONE);
									}
								}
						}
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_GENERIC:
						break;		
					}
					break;
							
				default:
				}
				
			} catch (NumberFormatException e) {							  
			}								
		}					
	}
	
	public static class AdjList_Combiner extends Reducer<Text, Text, Text, Text> {
		
		 StringBuilder sb = null;
		 
		 public void reduce(Text key, Iterable<Text> values, Context context) 
			      throws IOException, InterruptedException {
			 
			 sb = new StringBuilder();
			 
			 for (Text val : values) {
				 sb.append(val.toString());	
			 }
			 context.write(key, new Text(sb.toString()));
		 }
	 }
	
	public static class AdjList_Reducer extends Reducer<Text, Text, NullWritable, Text> {
		
		 StringBuilder sb = null;
		 
		 public void reduce(Text key, Iterable<Text> values, Context context) 
			      throws IOException, InterruptedException {
			 
			 sb = new StringBuilder();
			 sb.append(key.toString());
			 
			 for (Text val : values) {
				 sb.append(val.toString());	
			 }
			 context.write(NullWritable.get(), new Text(sb.toString()));
		 }
	 }
	
	private Job getJobConf(Job	job, String jobName, String strInpath, int reduces) throws IOException{
		
	    Path outPath = new Path(jobName+"_out/"+strInpath);			
		job.setJobName(jobName); 
		job.setJarByClass(RIB_Graph_AdjList.class);   
		job.setNumReduceTasks(reduces);   
			
		job.setInputFormatClass(BgpInputFormat.class);
		job.setOutputFormatClass(TextOutputFormat.class);
		job.setMapOutputKeyClass(Text.class);
		job.setMapOutputValueClass(Text.class);	
		
		job.setOutputKeyClass(NullWritable.class);
		job.setOutputValueClass(Text.class);	
		
		if(strInpath.contains("/"))
	        FileInputFormat.addInputPath(job, new Path(strInpath));
		else
			FileInputFormat.addInputPath(job, new Path(strInpath+"/RIBS"));
        FileOutputFormat.setOutputPath(job, outPath);
	
		job.setMapperClass(AdjList_Mapper.class);     
		job.setCombinerClass(AdjList_Combiner.class);
		job.setReducerClass(AdjList_Reducer.class);
		
		return job;
	}
		
	public boolean analysis(String strPath, int reduces) throws IOException, ClassNotFoundException, InterruptedException {
		
		Configuration conf = new Configuration();
		Job job = new Job(conf, "adjlist");		
		getJobConf(job, "adjlist", strPath, reduces); 
		FileSystem fs = FileSystem.get(conf);	
		
		// delete any output that might exist from a previous run of this job
		if (fs.exists(FileOutputFormat.getOutputPath(job))) {
			fs.delete(FileOutputFormat.getOutputPath(job), true);
		}
		job.waitForCompletion(true);
		return true;
	}
	
	
}
