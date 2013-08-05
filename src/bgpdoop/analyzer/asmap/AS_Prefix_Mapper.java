package bgpdoop.analyzer.asmap;

import java.io.IOException;
import java.util.Calendar;
import java.util.HashMap;

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
import org.apache.hadoop.mapreduce.Partitioner;
import org.apache.hadoop.mapreduce.Reducer;
import org.apache.hadoop.mapreduce.Mapper.Context;
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
import bgpdoop.analyzer.lib.TextPair;
import bgpdoop.hadoop.mapreduce.lib.input.BgpInputFormat;
import p3.hadoop.common.util.EZBytes;

/**
 * 
 * @author yhlee in Chungnam National University
 *  ssallys@naver.com
 */
public class AS_Prefix_Mapper {
		
	/*******************************************
			BGP Stats
	*******************************************/
	public static class ASMap_Mapper extends Mapper<LongWritable, BytesWritable, TextPair, NullWritable>{
		
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
		
		private final static int tic = 7200;
				
	    private final static IntWritable one = new IntWritable(1);

	    public void map(LongWritable key, BytesWritable value, Context context) 
	    		throws IOException, InterruptedException {	

			byte[] value_bytes = value.getBytes();
			eb = new EZBytes(value_bytes.length);
			eb.PutBytes(value_bytes, 0, value_bytes.length);
			pos=0;
			mrt = new MrtFormat();
			
			try{
				pos += mrt.parseMrtHeader(eb.GetBytes(pos,12));		
//				context.write(new Text("Entry Length"), new Text("type:"+mrt.type + " subtype:"+ mrt.subtype +" len:"+ mrt.length));
				
				cal = Calendar.getInstance();
				
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
						datestamp = mt.ldate - mt.ldate%tic;
						context.write(new TextPair(new Text(mt.prefix+"/"+mt.prefixLen+"|"), new Text(mt.attribute.aspaths.aspaths.toString().trim().substring(mt.attribute.aspaths.aspaths.toString().trim().lastIndexOf(" ")>0?mt.attribute.aspaths.aspaths.toString().trim().lastIndexOf(" "):0)
								+"|"+mt.ldate+"|")),  NullWritable.get());
					}
					break;
										
				/* TABLE_DUMP_V2 */
				case MrtFormat.BGPDUMP_TYPE_TABLE_DUMP_V2:				
					switch(mrt.subtype){
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_PEER_INDEX_TABLE:
						pe = new Tabledumpv2_PeerEntry();
						if((asn_len = pe.parsePIT(eb.GetBytes(pos)))>0){
							peerEntries=new HashMap<Integer,Long>();
							for(PeerEntry el : pe.peerEntries)
								peerEntries.put((int)el.pbid, el.pAS);
						}
						break;
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV4_UNICAST: case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV4_MULTICAST:
					case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV6_UNICAST: case MrtFormat.BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV6_MULTICAST:
						re = new Tabledumpv2_RibEntry();
						if(re.parseRibEntry(eb.GetBytes(pos), asn_len)>0){	  
							if(re.entryCnt>0)				
								for(RIBEntry entry:re.ribEntries){
									datestamp = entry.ldate-entry.ldate%tic;
									if(re.prefix != null && entry.attribute!=null);
										context.write(new TextPair(new Text(re.prefix+"/"+re.prefixLen+"|"), 
												new Text(entry.attribute.aspaths.aspaths.toString().trim().substring(entry.attribute.aspaths.aspaths.toString().trim().lastIndexOf(" ")>0
												?entry.attribute.aspaths.aspaths.toString().trim().lastIndexOf(" "):0)
												+"|"+entry.ldate+"|")), NullWritable.get());
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
/*	
	public static class ASMap_Combiner extends Reducer<Text, Text, Text, Text> {
		
		 int sum = 0;
		 public void reduce(Text key, Iterable<Text> values, Context context) 
			      throws IOException, InterruptedException {
			 sum = 0;
			 for (IntWritable val : values) {
				 sum += val.get();	
			 }
			 context.write(key, new IntWritable(sum));
		 }
	 }
*/	
	public static class ASMap_Reducer extends Reducer<TextPair, NullWritable, TextPair, NullWritable> {
		
		 public void reduce(TextPair key, Iterable<NullWritable> values, Context context) 
			      throws IOException, InterruptedException {
			 
			 for (NullWritable val : values) {
				 context.write(key, val);
			 }
			 
			 context.write(new TextPair(new Text("---------"), new Text("---------")), NullWritable.get());

		 }
	 }
	
	/*******************************************
		Partitioner & Comparators
	*******************************************/
	public static class FirstPartitioner extends Partitioner<TextPair, NullWritable> {
		
		@Override
		public int getPartition(TextPair key, NullWritable value, int numPartitions) {
			return Math.abs(key.getFirst().hashCode() * 127) % numPartitions;
		}
	}
	
	public static class KeyComparator extends WritableComparator {
		protected KeyComparator() {
			super(TextPair.class, true);
		}
		@Override
		public int compare(WritableComparable w1, WritableComparable w2) {
			TextPair ip1 = (TextPair) w1;
			TextPair ip2 = (TextPair) w2;
			return ip1.compareTo(ip2);
		}
	}
		
	public static class GroupComparator extends WritableComparator {
		protected GroupComparator() {
			super(TextPair.class, true);
		}		
		@Override
		public int compare(WritableComparable w1, WritableComparable w2) {
			TextPair ip1 = (TextPair) w1;
			TextPair ip2 = (TextPair) w2;
			return ip1.getFirst().compareTo(ip2.getFirst());
		}
	}
	
	private Job getJobConf(Job	job, String jobName, String month, int reduces) throws IOException{
		
		Path outPath = new Path(jobName+"_out");			
		job.setJobName(jobName); 
		job.setJarByClass(AS_Prefix_Mapper.class);   
		job.setNumReduceTasks(reduces);   
			
		job.setInputFormatClass(BgpInputFormat.class);
		job.setOutputFormatClass(TextOutputFormat.class);
		
		job.setMapOutputKeyClass(TextPair.class);
		job.setMapOutputValueClass(NullWritable.class);	
		
		job.setOutputKeyClass(TextPair.class);
		job.setOutputValueClass(NullWritable.class);	
		
	    FileInputFormat.addInputPath(job, new Path(month));
        FileOutputFormat.setOutputPath(job, outPath);
	
		job.setMapperClass(ASMap_Mapper.class);     
//		job.setCombinerClass(ASMap_Combiner.class);
		job.setReducerClass(ASMap_Reducer.class);
        job.setPartitionerClass(FirstPartitioner.class);        
//        job.set.setOutputKeyComparatorClass(KeyComparator.class);
        job.setGroupingComparatorClass(GroupComparator.class);
		
		return job;
	}
		
	public boolean analysis(String strPath, int reduces) throws IOException, ClassNotFoundException, InterruptedException {
		
		Configuration conf = new Configuration();
		Job job = new Job(conf, "asmap");		
		getJobConf(job, "asmap", strPath, reduces); 
		FileSystem fs = FileSystem.get(conf);	
		
		// delete any output that might exist from a previous run of this job
		if (fs.exists(FileOutputFormat.getOutputPath(job))) {
			fs.delete(FileOutputFormat.getOutputPath(job), true);
		}
		job.waitForCompletion(true);
		return true;
	}
	
	
}
