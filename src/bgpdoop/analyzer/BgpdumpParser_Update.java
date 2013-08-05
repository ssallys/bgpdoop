package bgpdoop.analyzer;

import java.io.IOException;
import java.util.Calendar;
import java.util.Iterator;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.PathFilter;
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
import bgpdoop.hadoop.mapreduce.lib.input.BgpInputFormat;
import p3.hadoop.common.util.EZBytes;

/**
 * 
 * @author yhlee in Chungnam National University
 *  ssallys@naver.com
 */
public class BgpdumpParser_Update {
	
	 public enum BGPTypeCounter {
			STATECHANGE,
			STATECHANGE4,
			MESSAGE,
			MESSAGE4
	}
	 
	/*******************************************
				BGP Stats
     *******************************************/
	public static class Map extends Mapper<LongWritable, BytesWritable, Text, Text>{
			
		EZBytes eb;
		MrtFormat mrt;
		Bgp4mp_Message bm;
		Bgp4mp_State bs;
		
		int pos;
		int cnt=0;
		int asn_len = 0;
		
		static final int IPV4 = 4;
		static final int IPV6 = 16;
		static final int AS2 = 2;
		static final int AS4 = 4;
		
		Text new_key = new Text();
		Text new_value = new Text();
		
		String date = null;
		Calendar cal;
	
	    public void map(LongWritable key, BytesWritable value, Context context) throws IOException, InterruptedException {	

			byte[] value_bytes = value.getBytes();
			eb = new EZBytes(value_bytes.length);
			eb.PutBytes(value_bytes, 0, value_bytes.length);
			pos=0;
			mrt = new MrtFormat();
			
			try{
				pos += mrt.parseMrtHeader(eb.GetBytes(pos,12));		
/*
 				new_key.set("Entry Length");
				new_value.set("type:"+mrt.type + " subtype:"+ mrt.subtype +" len:"+ mrt.length);	
				context.write(new_key, new_value);
*/				
				cal = Calendar.getInstance();
				cal.setTimeInMillis(mrt.timestamp*1000);
				cal.set(Calendar.HOUR, -5); // set time to Europ
				date = String.format("%1$tY-%1$tm-%1$td %1$tH:%1$tM:%1$tS", cal);
				
				switch (mrt.type){	
						
				// BGP4MP //	
				case MrtFormat.BGPDUMP_TYPE_BGP4MP:				
					switch(mrt.subtype){
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_STATE_CHANGE: 
						bs = new Bgp4mp_State();
						if(bs.parseStateChange(eb.GetBytes(pos, (int)mrt.length))){
							new_key.set("bgp_state");
							new_value.set(bs.toString());
//							context.write(new_key, new_value);
//							if(bs.new_state==Bgp4mp_Attributes.BGP_STATE_ESTABLISHED)
								context.getCounter(BGPTypeCounter.STATECHANGE).increment(1);
						}
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_STATE_CHANGE_AS4:
						bs = new Bgp4mp_State();
						if(bs.parseStateChange4(eb.GetBytes(pos, (int)mrt.length)))	{						
							new_key.set("bgp_stateAs4");
							new_value.set(bs.toString());
//							context.write(new_key, new_value);
//							if(bs.new_state==Bgp4mp_Attributes.BGP_STATE_ESTABLISHED)
								context.getCounter(BGPTypeCounter.STATECHANGE4).increment(1);
						}
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_MESSAGE:
						bm = new Bgp4mp_Message();
						if(bm.parseMessage(eb.GetBytes(pos, (int)mrt.length), 2)){
							new_key.set("bgp_message");
							new_value.set(date+"|"+bm.toString());
							context.write(new_key, new_value);
							context.getCounter(BGPTypeCounter.MESSAGE).increment(1);
						}
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_MESSAGE_AS4:
						bm = new Bgp4mp_Message();
						if(bm.parseMessage(eb.GetBytes(pos, (int)mrt.length), 4)){
							new_key.set("bgp_messageAs4");
							new_value.set(date+"|"+bm.toString());
							context.write(new_key, new_value);
							context.getCounter(BGPTypeCounter.MESSAGE4).increment(1);
						}
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_ENTRY:
						break;
						
					case MrtFormat.BGPDUMP_SUBTYPE_BGP4MP_SNAPSHOT:
						break;	
					default:						
					}
				default:						
				}					
			} catch (NumberFormatException e) {							  
			}								
		}		
		public void close(){
		}		
	}
   

	public class Reduce extends Reducer<Text, Text, NullWritable, Text> {
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
	
    private Job getJobConf(Job	job, String jobName, String strInpath, int reduces) throws IOException{
				
        job.setJobName(jobName); 
        job.setJarByClass(BgpdumpParser_Update.class);   
        job.setNumReduceTasks(reduces);   
        
        job.setMapOutputKeyClass(Text.class);
        job.setMapOutputValueClass(Text.class);	
        
        job.setOutputKeyClass(NullWritable.class);
        job.setOutputValueClass(Text.class);	     
        
        job.setMapperClass(Map.class); 
//        job.setCombinerClass(Reduce.class);
//        job.setReducerClass(Reduce.class); 
        
        job.setInputFormatClass(BgpInputFormat.class);  
        job.setOutputFormatClass(TextOutputFormat.class);    
        		
	    Path outPath = new Path(jobName+"_out/"+strInpath);	
        FileOutputFormat.setOutputPath(job, outPath);
        
//		MultipleInputs.addInputPath(job, bgpPath, BgpInputFormat.class, BgpUpdate_Mapper.class);
//		MultipleInputs.addInputPath(job, new Path("2011.01/UPDATES"), BgpInputFormat.class, BgpUpdate_Mapper.class);
        
        return job;
	}
	
	public boolean analysis(String inputDir, int reduces) throws IOException, ClassNotFoundException, InterruptedException {
	    
		Configuration conf = new Configuration();
		Job job = new Job(conf, "parseUpdate");
		
	    getJobConf(job, "parseUpdate", inputDir, reduces); 
	    FileSystem fs = FileSystem.get(conf);  

	    Path inPath = null;
	    
		if(inputDir.endsWith(".gz") || inputDir.endsWith(".bz2"))
			inPath = new Path(inputDir);
		else
			inPath = new Path(inputDir+"/UPDATES");

        FileInputFormat.addInputPath(job, inPath);
//        fs.globStatus(inPath, new RegexExcludePathFilter("^updates$..*"));
        
		// delete any output that might exist from a previous run of this job
		if (fs.exists(FileOutputFormat.getOutputPath(job))) {
		  fs.delete(FileOutputFormat.getOutputPath(job), true);
	    }
		
	    job.waitForCompletion(true);  
	    return true;
	}
	
	public class RegexExcludePathFilter implements PathFilter {
		
		private final String regex;
		
		public RegexExcludePathFilter(String regex) {
			this.regex = regex;
		}

		public boolean accept(org.apache.hadoop.fs.Path path) {
			// TODO Auto-generated method stub
			return path.toString().matches(regex);
		}
	}
 }
