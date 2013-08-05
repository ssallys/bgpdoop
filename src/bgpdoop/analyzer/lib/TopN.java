package bgpdoop.analyzer.lib;

import java.io.IOException;
import java.util.Iterator;

import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.JobClient;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.MapReduceBase;
import org.apache.hadoop.mapred.Mapper;
import org.apache.hadoop.mapred.OutputCollector;
import org.apache.hadoop.mapred.Reducer;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.mapred.TextInputFormat;
import org.apache.hadoop.mapred.TextOutputFormat;

public class TopN {
   	
	static JobConf conf = new JobConf(TopN.class);
		
	/*******************************************
			Stream Generation Job
	*******************************************/
	public static class Map_StatStream extends MapReduceBase 
	implements Mapper<LongWritable, Text, LongWritable, Text>{
		
		int k = 0;
		int count = 0;
		int field = 0;

		public void configure(JobConf job) {
			k = job.getInt("mapred.reduce.topk.k", 10);
			field = job.getInt("mapred.reduce.topk.field", 2);
			count = 0;
		}

		public void map
				(LongWritable key, Text value, 
				OutputCollector<LongWritable, Text> output, Reporter reporter) throws IOException {		

			long new_key = 0;
			String arrval[] = value.toString().split("\t");
			if (arrval.length <2)
				arrval = value.toString().split(" ");
//			StringTokenizer stok = new StringTokenizer(value.toString());
//			if(arrval.length < 50) return;
//			if(stok.countTokens()<50) return;
			new_key = Long.parseLong(arrval[field-1]);
			output.collect(new LongWritable(new_key), value);
		}
	}

	/*******************************************
			Stream Reducing Job
	*******************************************/
	public static class Reduce_StatStream extends MapReduceBase 
	implements Reducer<LongWritable, Text, LongWritable, Text> {
		
		int k = 0;
		int count = 0;

		public void configure(JobConf job) {
			k = job.getInt("mapred.reduce.topk.k", 10);
			count = 0;
		}
			
		public void reduce(LongWritable key, Iterator<Text> value,
		    OutputCollector<LongWritable, Text> output, Reporter reporter)
		    throws IOException {

//			BytesWritable bw = new BytesWritable();
			while(value.hasNext() && count++ < k){ 	
					output.collect(key, value.next());
			}
		}
	}

    private static JobConf getMakeStreamJobConf(String jobName, Path inPath, Path outPath, int fieldNo, int k){		
		
        conf.setJobName(jobName); 
        conf.setNumReduceTasks(1);    
        
        conf.setMapOutputKeyClass(LongWritable.class);        
        conf.setOutputKeyClass(LongWritable.class);     
        
        conf.setInputFormat(TextInputFormat.class);   
        conf.setOutputFormat(TextOutputFormat.class);       
        
        conf.setOutputKeyComparatorClass(LongWritable.DecreasingComparator.class);
        conf.setMapperClass(Map_StatStream.class);  
        conf.setCombinerClass(Reduce_StatStream.class);
        conf.setReducerClass(Reduce_StatStream.class); 
        
		conf.setInt("mapred.reduce.topk.field", fieldNo);
		conf.setInt("mapred.reduce.topk.k", k);
        
        FileInputFormat.setInputPaths(conf, inPath);
        FileOutputFormat.setOutputPath(conf, outPath);        
        return conf;
	}

    public static void startTopN(Path inPath, Path outPath, int fieldNo, int k) throws IOException {   	
        FileSystem fs = FileSystem.get(conf);
        JobConf genStreamJob = getMakeStreamJobConf("TopN", inPath, outPath, fieldNo, k);        
        // delete any output that might exist from a previous run of this job
        if (fs.exists(FileOutputFormat.getOutputPath(genStreamJob))) {
          fs.delete(FileOutputFormat.getOutputPath(genStreamJob), true);
        }
        JobClient.runJob(genStreamJob); 
	}
}
