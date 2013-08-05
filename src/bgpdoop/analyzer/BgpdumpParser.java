package bgpdoop.analyzer;

import java.io.IOException;
import java.util.Iterator;

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
import bgpdoop.hadoop.mapreduce.lib.input.BgpInputFormat;
import p3.hadoop.common.util.EZBytes;

/**
 * 
 * @author yhlee in Chungnam National University
 *  ssallys@naver.com
 */
public class BgpdumpParser {
	
	/*******************************************
				BGP Stats
     *******************************************/
	public static class Map extends Mapper<LongWritable, BytesWritable, Text, Text>{
			
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
		
		static final int IPV4 = 4;
		static final int IPV6 = 16;
		static final int AS2 = 2;
		static final int AS4 = 4;
		
		Text new_key = new Text();
		Text new_value = new Text();
		
	    public void map(LongWritable key, BytesWritable value, Context context) throws IOException, InterruptedException {	

			byte[] value_bytes = value.getBytes();
			eb = new EZBytes(value_bytes.length);
			eb.PutBytes(value_bytes, 0, value_bytes.length);
			pos=0;
			mrt = new MrtFormat();
			
			try{
				pos += mrt.parseMrtHeader(eb.GetBytes(pos,12));		
//				new_key.set("Entry Length"); new_value.set("type:"+mrt.type + " subtype:"+ mrt.subtype +" len:"+ mrt.length);
//if(1==1) return;				
				switch (mrt.type){	
				
				// TABLE_DUMP_V2 //
				case MrtFormat.BGPDUMP_TYPE_MRTD_TABLE_DUMP:				
					switch(mrt.subtype){
					case MrtFormat.BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP: 
						mt = new Tabledump_Mrtd();
						if(mt.parseRibEntry(eb.GetBytes(pos), IPV4, AS2)){
							new_key.set("RIB_Entry");
							new_value.set(mt.toString());context.write(new_key, new_value);
						}
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP_32BIT_AS:
						if(mt.parseRibEntry(eb.GetBytes(pos), IPV4, AS4)){
							new_key.set("RIB_Entry");
							new_value.set(mt.toString());context.write(new_key, new_value);
						}
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP6: 
						mt = new Tabledump_Mrtd();
						if(mt.parseRibEntry(eb.GetBytes(pos), IPV6, AS2)){
							new_key.set("RIB_Entry");
							new_value.set(mt.toString());context.write(new_key, new_value);
						}
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP6_32BIT_AS:
						mt = new Tabledump_Mrtd();
						if(mt.parseRibEntry(eb.GetBytes(pos), IPV6, AS4)){
							new_key.set("RIB_Entry");
							new_value.set(mt.toString());context.write(new_key, new_value);
						}
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_GENERIC:
						break;		
					}
					break;
					
				// TABLE_DUMP_V2 //
				case MrtFormat.BGPDUMP_TYPE_TABLE_DUMP_V2:				
					switch(mrt.subtype){
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_PEER_INDEX_TABLE:
						pe = new Tabledumpv2_PeerEntry();
						if((asn_len = pe.parsePIT(eb.GetBytes(pos)))>0){
							new_key.set("PITv2_Entry");
							new_value.set(pe.toString());context.write(new_key, new_value);
						}
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV4_UNICAST: case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV4_MULTICAST:
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV6_UNICAST: case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV6_MULTICAST:
						re = new Tabledumpv2_RibEntry();
//						if(cnt>1000) return;
						if(re.parseRibEntry(eb.GetBytes(pos), 4)>0){							
							new_key.set("RIBv2_Entry");
							new_value.set(re.toString());context.write(new_key, new_value);
//							cnt++;
						}
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_GENERIC:
						break;		
					}
					break;
					
				// BGP4MP //	
				case MrtFormat.BGPDUMP_TYPE_BGP4MP:				
					switch(mrt.subtype){
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_STATE_CHANGE: 
						if(bs.parseStateChange(eb.GetBytes(pos))){
							new_key.set("bgp_state");
							new_value.set(bs.toString());context.write(new_key, new_value);
						}
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_STATE_CHANGE_AS4:
						bs = new Bgp4mp_State();
						if(bs.parseStateChange4(eb.GetBytes(pos)))	{						
							new_key.set("bgp_stateAs4");
							new_value.set(bs.toString());
							context.write(new_key, new_value);
						}
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_MESSAGE:
						bm = new Bgp4mp_Message();
						if(bm.parseMessage(eb.GetBytes(pos), 2)){
							new_key.set("bgp_message");
							new_value.set(bm.toString());context.write(new_key, new_value);
						}
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_MESSAGE_AS4:
						bm = new Bgp4mp_Message();
						if(bm.parseMessage(eb.GetBytes(pos), 4)){
							new_key.set("bgp_messageAs4");
							new_value.set(bm.toString());context.write(new_key, new_value);
						}
//						else
//							if(bm.len0)	reporter.incrCounter(COUNTER_KEYS.INVALID_LINES, 1);
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_ENTRY:
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_SNAPSHOT:
						break;	
					default:						
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
   

	public static class Reduce extends Reducer<Text, Text, NullWritable, Text> {
		int sum = 0;
		Text new_value = new Text();
		public void reduce(Text key, Iterator<Text> value, Context context)
            throws IOException, InterruptedException {
			
	    	MrtFormat ub = new MrtFormat();
	    	new_value.set(ub.toString());
			while(value.hasNext()){ 				
				value.next();				
				context.write(NullWritable.get(), new_value);				
			}				
	    }
	}
	
    private Job getJobConf(Job	job, String jobName, Path inFilePath, String ds) throws IOException{
		
	    Path Output = new Path(jobName+"_out"+"/"+ds);			
        job.setJobName(jobName); 
        job.setJarByClass(BgpdumpParser.class);   
        job.setNumReduceTasks(0);   
        
        job.setMapOutputKeyClass(Text.class);
        job.setMapOutputValueClass(Text.class);	
        
        job.setOutputKeyClass(NullWritable.class);
        job.setOutputValueClass(Text.class);	     
        
        job.setMapperClass(Map.class);     
        job.setCombinerClass(Reduce.class);
        
        job.setInputFormatClass(BgpInputFormat.class);  
        job.setOutputFormatClass(TextOutputFormat.class);    

        job.setReducerClass(Reduce.class); 

        FileInputFormat.addInputPath(job, inFilePath);
        FileOutputFormat.setOutputPath(job, Output);
        
        return job;
	}
	
	public boolean analysis(Path inputDir, String ds) throws IOException, ClassNotFoundException, InterruptedException {
	    
		Configuration conf = new Configuration();
		Job job = new Job(conf, "parse");
		
	    getJobConf(job, "parse", inputDir, ds); 
	    FileSystem fs = FileSystem.get(conf);
	
		// delete any output that might exist from a previous run of this job
		if (fs.exists(FileOutputFormat.getOutputPath(job))) {
		  fs.delete(FileOutputFormat.getOutputPath(job), true);
	    }
		
	    job.waitForCompletion(true);  
	    return true;
	}
 }
