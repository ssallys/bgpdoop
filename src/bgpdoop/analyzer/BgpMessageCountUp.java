package bgpdoop.analyzer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.StringTokenizer;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.IntWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.NullWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.WritableComparable;
import org.apache.hadoop.io.WritableComparator;

import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.mapreduce.Reducer;
import org.apache.hadoop.mapreduce.Mapper.Context;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.input.MultipleInputs;
import org.apache.hadoop.mapreduce.lib.input.TextInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.MultipleOutputs;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;

import bgpdoop.analyzer.lib.Bgp4mp_Message;
import bgpdoop.analyzer.lib.Bgp4mp_State;
import bgpdoop.analyzer.lib.MrtFormat;
import bgpdoop.analyzer.lib.Tabledump_Mrtd;
import bgpdoop.analyzer.lib.Tabledumpv2_PeerEntry;
import bgpdoop.analyzer.lib.Tabledumpv2_RibEntry;
import bgpdoop.analyzer.lib.TopN;
import bgpdoop.hadoop.mapreduce.lib.input.BgpInputFormat;
import p3.hadoop.common.util.EZBytes;

/**
 * 
 * @author yhlee in Chungnam National University
 *  ssallys@naver.com
 */
public class BgpMessageCountUp {
		
	/*******************************************
		BGP Stats
	*******************************************/
	public static class BgpMessageCnt_Mapper extends Mapper<LongWritable, BytesWritable, Text, IntWritable>{
		
		EZBytes eb;
		MrtFormat mrt = new MrtFormat();
		Bgp4mp_Message bm;
		Bgp4mp_State bs;
		Tabledumpv2_PeerEntry pe;
		Tabledumpv2_RibEntry re;
		Tabledump_Mrtd mt;
		int pos;
		int cnt=0;
		int asn_len = 0;
		
	    private final static IntWritable one = new IntWritable(1);

	    public void map(LongWritable key, BytesWritable value, Context context) 
	    		throws IOException, InterruptedException {	

			byte[] value_bytes = value.getBytes();
			eb = new EZBytes(value_bytes.length);
			eb.PutBytes(value_bytes, 0, value_bytes.length);
			pos=0;
			
			try{
				pos += mrt.parseMrtHeader(eb.GetBytes(pos,12));		
//				context.write(new Text("Entry Length"), new Text("type:"+mrt.type + " subtype:"+ mrt.subtype +" len:"+ mrt.length));
				
				switch (mrt.type){	
				/* omit tabledump records */
					
				/* BGP4MP */	
				case MrtFormat.BGPDUMP_TYPE_BGP4MP:
					
					switch(mrt.subtype){
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_STATE_CHANGE: 
						bs = new Bgp4mp_State();
						if(bs.parseStateChange(eb.GetBytes(pos)))
							context.write(new Text("AS"+bs.peer_as), one);
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_STATE_CHANGE_AS4:
						bs = new Bgp4mp_State();
						if(bs.parseStateChange4(eb.GetBytes(pos)))							
							context.write(new Text("AS"+bs.peer_as), one);
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_MESSAGE:
						bm = new Bgp4mp_Message();
						if(bm.parseMessage(eb.GetBytes(pos), 2))
							context.write(new Text("AS"+bm.peer_as), one);
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_MESSAGE_AS4:
						bm = new Bgp4mp_Message();
						if(bm.parseMessage(eb.GetBytes(pos), 4))
							context.write(new Text("AS"+bm.peer_as), one);
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
	
	public static class BgpMessageCnt_Reducer extends Reducer<Text, IntWritable, Text, IntWritable> {
				
		 public void reduce(Text key, Iterable<IntWritable> values, Context context) 
			      throws IOException, InterruptedException {
			 int sum = 0;
			 for (IntWritable val : values) {
				 sum += val.get();
			 }
			 context.write(key, new IntWritable(sum));
		 }
	}
	
	public static class Asn_Mapper extends Mapper<LongWritable, Text, Text, Text>{
 		
		String line = null;
		String prefix;
		
		public void map(LongWritable key, Text value, Context context) throws IOException, InterruptedException {	
			line = value.toString();
			StringTokenizer stok = new StringTokenizer(line,"|");
//			while(stok.hasMoreTokens()){
				stok.nextToken();
				stok.nextToken();
				stok.nextToken();
				prefix = stok.nextToken();
//			}
			context.write(new Text(prefix), new Text("asn|"+line));
		}
	}
	
		
	private Job getJobConf(Job	job, String jobName, String	strInpath, Path asnPath, int reduces) throws IOException{
		
	    Path outPath = new Path(jobName+"_out/"+strInpath);			
		job.setJobName(jobName); 
		job.setJarByClass(BgpMessageCountUp.class);   
		job.setNumReduceTasks(reduces);   
			
		job.setInputFormatClass(BgpInputFormat.class);
		job.setOutputFormatClass(TextOutputFormat.class);
		
		job.setOutputKeyClass(Text.class);
		job.setOutputValueClass(IntWritable.class);	     
		
        FileInputFormat.addInputPath(job, new Path(strInpath));
        FileOutputFormat.setOutputPath(job, outPath);
        	
		job.setMapperClass(BgpMessageCnt_Mapper.class);     
		job.setCombinerClass(BgpMessageCnt_Reducer.class);
		job.setReducerClass(BgpMessageCnt_Reducer.class);
		
		return job;
	}
		
	public boolean analysis(String strInpath, Path asnPath, int reduces) throws IOException, ClassNotFoundException, InterruptedException {
		
		Configuration conf = new Configuration();
		Job job = new Job(conf, "count");		
		getJobConf(job, "count", strInpath, asnPath, reduces); 
		FileSystem fs = FileSystem.get(conf);	
		
		// delete any output that might exist from a previous run of this job
		if (fs.exists(FileOutputFormat.getOutputPath(job))) {
			fs.delete(FileOutputFormat.getOutputPath(job), true);
		}
		job.waitForCompletion(true); 		
		
		return true;
	}
	
	
}
