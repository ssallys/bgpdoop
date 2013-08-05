package bgpdoop.runner;

import java.io.IOException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.mapreduce.lib.output.TextOutputFormat;

import bgpdoop.hadoop.mapreduce.lib.input.BgpRibInputFormat;

/**
 * 
 * @author yhlee of the Chungnam National University
 *  ssallys@naver.com
 */
public class Test {
	
	public static class MyMapper extends Mapper<LongWritable, ObjectWritable, LongWritable, ObjectWritable>{
	    public void map(LongWritable key, ObjectWritable value, Context context) 
	    		throws IOException, InterruptedException {	
			context.write(key, value);							
		}						
	}

	public void run(String inpath) throws IOException{
		
		Path outpath = new Path("test");

		Configuration conf = new Configuration();
		Job job = new Job(conf);

		job.setMapperClass(MyMapper.class);  
		job.setJobName("myjob"); 
		job.setJarByClass(Test.class);   
		job.setNumReduceTasks(1);   
		
		job.setInputFormatClass(BgpRibInputFormat.class);
		job.setOutputFormatClass(TextOutputFormat.class);
		
		job.setOutputKeyClass(LongWritable.class);
		job.setOutputValueClass(ObjectWritable.class);	     
	
		FileInputFormat.addInputPath(job, new Path(inpath));
	    FileOutputFormat.setOutputPath(job, outpath);
    
		FileSystem fs = FileSystem.get(conf);	
		// delete any output that might exist from a previous run of this job
		if (fs.exists(FileOutputFormat.getOutputPath(job))) {
			fs.delete(FileOutputFormat.getOutputPath(job), true);
		}		
		try {
			job.waitForCompletion(true);
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
		
	public static void main(String[] args) throws Exception{
		new Test().run(args[0]);
	}
}
